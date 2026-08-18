"""Mirror the GT-T managed-host set into the customer NetBox.

The GT-T NetBox is the record of truth for managed devices; the customer
instance carries a synced copy so local tooling and operators see the same
inventory. Runs after every successful managed-host sync.

Idempotency: each mirrored object is tracked in Redis (inv:mirror,
host_id -> {customer NetBox id, content fingerprint}); hosts whose
fingerprint is unchanged are skipped without a single API call. Mirrored
objects carry the `halo-managed` tag. Hosts that drop out of the GT-T set
are marked offline in the customer NetBox — never deleted.
"""

import hashlib
import json
import logging
import time

import httpx

from app.config import settings
from app.services import netbox_write, store
from app.services.netbox import _slugify

logger = logging.getLogger("inventory.mirror")

MANAGED_TAG = {"name": "halo-managed", "slug": "halo-managed", "color": "2196f3"}
# NetBox's writable tags field takes dicts, never bare integer ids.
TAG_REF = [{"name": MANAGED_TAG["name"], "slug": MANAGED_TAG["slug"]}]

# Introspection for GET /inventory/status; updated each cycle.
last_run: dict = {"at": None, "hosts": 0, "created": 0, "updated": 0,
                  "unchanged": 0, "retired": 0, "failed": 0, "error": None}

# Every field the mirror pushes must be in the fingerprint basis, or drift
# in that field would be skipped as "unchanged" forever.
FP_FIELDS = ("name", "model", "manufacturer", "role", "site", "status",
             "platform", "serial", "primary_ip", "cluster", "vcpus",
             "memory", "disk")


def _fingerprint(host: dict) -> str:
    basis = {k: host.get(k) for k in FP_FIELDS}
    basis["ips"] = sorted(host.get("ips") or [])
    basis["cidrs"] = host.get("cidrs") or {}
    return hashlib.sha1(
        json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()


def _status_value(host: dict) -> str:
    """Normalized records hold the status label ("Active"); the write API
    wants the value ("active")."""
    label = (host.get("status") or "Active").strip()
    return label.lower().replace(" ", "-") or "active"


def _base_path(kind: str) -> str:
    return ("/api/dcim/devices/" if kind == "device"
            else "/api/virtualization/virtual-machines/")


async def _ensure_named(client: httpx.AsyncClient, kind: str, name: str,
                        api_path: str, extra: dict | None = None) -> int:
    slug = _slugify(name)
    return await netbox_write._ensure(
        client, f"{kind}:{slug}", f"{api_path}?slug={slug}", api_path,
        {"name": name, "slug": slug, **(extra or {})})


async def _ensure_device_type(client: httpx.AsyncClient, model: str,
                              manufacturer_id: int) -> int:
    slug = _slugify(model)
    return await netbox_write._ensure(
        client, f"devicetype:{slug}", f"/api/dcim/device-types/?slug={slug}",
        "/api/dcim/device-types/",
        {"model": model, "slug": slug, "manufacturer": manufacturer_id})


async def _ensure_cluster(client: httpx.AsyncClient, name: str) -> int:
    """Clusters have no slug; look up by name, create under an 'Unknown'
    cluster type when absent."""
    cache_key = f"cluster:{_slugify(name)}"
    cached = await store.get_nbid(cache_key)
    if cached:
        return cached
    results = await netbox_write._get_results(
        client, f"/api/virtualization/clusters/?{httpx.QueryParams({'name': name})}")
    if results:
        nbid = results[0]["id"]
    else:
        type_id = await _ensure_named(client, "clustertype", "Unknown",
                                      "/api/virtualization/cluster-types/")
        nbid = (await netbox_write._post(
            client, "/api/virtualization/clusters/",
            {"name": name, "type": type_id}))["id"]
    await store.set_nbid(cache_key, nbid)
    return nbid


async def _build_payload(client: httpx.AsyncClient, host: dict) -> dict:
    payload = {"name": host["name"], "status": _status_value(host),
               "tenant": settings.NETBOX_TENANT_ID, "tags": list(TAG_REF)}
    if host.get("platform"):
        payload["platform"] = await _ensure_named(
            client, "platform", host["platform"], "/api/dcim/platforms/")
    if host.get("kind") == "vm":
        if host.get("cluster"):
            payload["cluster"] = await _ensure_cluster(client, host["cluster"])
        # A VM needs a cluster or a site; fall back to Unassigned.
        if host.get("site") or "cluster" not in payload:
            payload["site"] = await _ensure_named(
                client, "site", host.get("site") or "Unassigned", "/api/dcim/sites/")
        for field in ("vcpus", "memory", "disk"):
            if host.get(field) is not None:
                payload[field] = host[field]
        return payload
    manufacturer_id = await _ensure_named(
        client, "manufacturer", host.get("manufacturer") or "Unknown",
        "/api/dcim/manufacturers/")
    payload["device_type"] = await _ensure_device_type(
        client, host.get("model") or "Unknown", manufacturer_id)
    payload["role"] = await _ensure_named(
        client, "role", host.get("role") or "Managed", "/api/dcim/device-roles/")
    payload["site"] = await _ensure_named(
        client, "site", host.get("site") or "Unassigned", "/api/dcim/sites/")
    payload["serial"] = host.get("serial") or ""
    return payload


async def _sync_ips(client: httpx.AsyncClient, host: dict, nbid: int, kind: str) -> None:
    """Attach every known IP to a single mirror interface and set the
    primary. IPs assigned to some other object are left alone — the mirror
    never steals addresses."""
    ips = host.get("ips") or []
    if not ips:
        return
    if kind == "device":
        if_path, owner_field, owner_param = "/api/dcim/interfaces/", "device", "device_id"
        obj_type = "dcim.interface"
    else:
        if_path, owner_field, owner_param = ("/api/virtualization/interfaces/",
                                             "virtual_machine", "virtual_machine_id")
        obj_type = "virtualization.vminterface"
    found = await netbox_write._get_results(
        client, f"{if_path}?{owner_param}={nbid}&name=eth0")
    if found:
        if_id = found[0]["id"]
    else:
        if_payload = {owner_field: nbid, "name": "eth0"}
        if kind == "device":
            if_payload["type"] = "other"
        if_id = (await netbox_write._post(client, if_path, if_payload))["id"]

    primary_bare = (host.get("primary_ip") or "").split("/")[0]
    primary_patch = {}
    for ip in ips:
        existing = await netbox_write._get_results(
            client, f"/api/ipam/ip-addresses/?{httpx.QueryParams({'address': ip})}")
        ip_obj = existing[0] if existing else None
        if ip_obj and ip_obj.get("assigned_object_id"):
            if (ip_obj.get("assigned_object_type") != obj_type
                    or ip_obj.get("assigned_object_id") != if_id):
                logger.warning("IP %s already assigned to another object in the "
                               "customer NetBox; leaving it (host %s)",
                               ip, host["host_id"])
                continue
        elif ip_obj:
            ip_obj = await netbox_write._patch(
                client, f"/api/ipam/ip-addresses/{ip_obj['id']}/",
                {"assigned_object_type": obj_type, "assigned_object_id": if_id})
        else:
            # Real CIDR from GT-T when known; host-route fallback otherwise.
            address = (host.get("cidrs") or {}).get(ip) \
                or f"{ip}/{128 if ':' in ip else 32}"
            ip_obj = await netbox_write._post(client, "/api/ipam/ip-addresses/", {
                "address": address, "status": "active",
                "tenant": settings.NETBOX_TENANT_ID,
                "assigned_object_type": obj_type, "assigned_object_id": if_id})
        if ip == primary_bare:
            primary_patch["primary_ip6" if ":" in ip else "primary_ip4"] = ip_obj["id"]
    if primary_patch:
        await netbox_write._patch(client, f"{_base_path(kind)}{nbid}/", primary_patch)


async def _upsert_host(client: httpx.AsyncClient, host: dict,
                       entry: dict | None) -> tuple[int, str]:
    """Create or update one host in the customer NetBox. Returns
    (customer NetBox id, "created" | "updated"). Adopting an existing
    same-named object upgrades discovery placeholders in place."""
    kind = host.get("kind", "device")
    base = _base_path(kind)
    payload = await _build_payload(client, host)
    nbid = entry.get("id") if entry else None
    action = "updated"
    if not nbid:
        found = await netbox_write._get_results(
            client, f"{base}?{httpx.QueryParams({'name__ie': host['name']})}")
        if found:
            nbid = found[0]["id"]
    if nbid:
        try:
            await netbox_write._patch(client, f"{base}{nbid}/", payload)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            nbid = None  # tracked object was deleted out from under us
    if not nbid:
        payload["comments"] = (
            f"Mirrored from GT-T NetBox ({host['host_id']}) by Defense Halo "
            f"on {time.strftime('%Y-%m-%d', time.gmtime())}")
        nbid = (await netbox_write._post(client, base, payload))["id"]
        action = "created"
    await _sync_ips(client, host, nbid, kind)
    return nbid, action


async def mirror_managed_hosts(hosts: list) -> dict:
    """One mirror pass over the full managed set. Per-host failures are
    counted and logged, never fatal; a wholesale failure (customer NetBox
    down) is recorded in last_run.error."""
    result = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "hosts": len(hosts), "created": 0, "updated": 0,
              "unchanged": 0, "retired": 0, "failed": 0, "error": None}
    try:
        mapping = await store.get_mirror_map()
        async with httpx.AsyncClient(timeout=30,
                                     verify=settings.NETBOX_VERIFY_SSL) as client:
            # Existence/color only; assignment uses TAG_REF dicts.
            await netbox_write._ensure(
                client, "tag:halo-managed", "/api/extras/tags/?slug=halo-managed",
                "/api/extras/tags/", MANAGED_TAG)
            seen = set()
            for host in hosts:
                host_id = host.get("host_id")
                if not host_id or not (host.get("name") or "").strip():
                    continue
                seen.add(host_id)
                fp = _fingerprint(host)
                entry = mapping.get(host_id)
                if entry and entry.get("fp") == fp:
                    result["unchanged"] += 1
                    continue
                try:
                    nbid, action = await _upsert_host(client, host, entry)
                    await store.set_mirror_entry(host_id, nbid, fp)
                    result[action] += 1
                except httpx.HTTPStatusError as exc:
                    # Message carries the NetBox error body (see
                    # netbox_write._check); no traceback needed.
                    logger.error("mirror failed for %s: %s", host_id, exc)
                    result["failed"] += 1
                except Exception:
                    logger.exception("mirror failed for %s", host_id)
                    result["failed"] += 1
            # Hosts that left the GT-T managed set: mark offline, never delete.
            for host_id, entry in mapping.items():
                if host_id in seen:
                    continue
                if entry.get("id"):
                    kind = "vm" if host_id.startswith("vm:") else "device"
                    try:
                        await netbox_write._patch(
                            client, f"{_base_path(kind)}{entry['id']}/",
                            {"status": "offline"})
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code != 404:
                            logger.warning("failed to retire %s: %s", host_id, exc)
                await store.delete_mirror_entry(host_id)
                result["retired"] += 1
        logger.info("mirror ok: %(created)d created, %(updated)d updated, "
                    "%(unchanged)d unchanged, %(retired)d retired, "
                    "%(failed)d failed", result)
    except Exception as exc:
        logger.exception("mirror cycle crashed")
        result["error"] = str(exc)
    last_run.clear()
    last_run.update(result)
    return result
