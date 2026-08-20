import asyncio
import re

import httpx

from app.clients import cmd_client
from app.config import settings
from app.services import store

# CMD custom field format is "{gnid}-{segment_id}"; segment_id is the trailing int.
CMD_SEGMENT_ID_PATTERN = re.compile(r"-(\d+)$")
# Placeholder site name NetBox falls back to when no real location is set.
NETBOX_GENERIC_SITE_NAME = "CST"


def _headers(token: str) -> dict:
    return {"Authorization": f"Token {token}", "Accept": "application/json"}


def _rebase(next_url: str | None, base_url: str) -> str | None:
    """NetBox behind a TLS-terminating proxy emits http:// pagination links;
    force every "next" URL back onto the configured scheme/host/port."""
    if not next_url:
        return None
    base = httpx.URL(base_url)
    return str(httpx.URL(next_url).copy_with(
        scheme=base.scheme, host=base.host, port=base.port or None))


async def _fetch_all(client: httpx.AsyncClient, base_url: str, token: str, path: str) -> list:
    """Follow NetBox pagination until exhausted. Raises on HTTP errors,
    naming the exact URL that failed."""
    results, url = [], f"{base_url}{path}"
    while url:
        try:
            resp = await client.get(url, headers=_headers(token))
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"NetBox request failed for {url}: {type(exc).__name__}: {exc}") from exc
        resp.raise_for_status()
        payload = resp.json()
        results.extend(payload.get("results", []))
        url = _rebase(payload.get("next"), base_url)
    return results


def _bare_ip(address: str | None) -> str | None:
    return address.split("/")[0] if address else None


def _clean_version(value) -> str | None:
    """Normalize placeholder junk ('None', 'null', 'unknown', empty) to None
    so downstream CVE queries never search for a literal 'FortiOS None'."""
    if value is None:
        return None
    s = str(value).strip()
    return None if not s or s.lower() in ("none", "null", "unknown", "n/a") else s


def _normalize_device(d: dict) -> dict:
    primary = (d.get("primary_ip4") or d.get("primary_ip6") or {}).get("address")
    return {
        "kind": "device",
        "id": d.get("id"),
        "host_id": f"device:{d.get('id')}",
        "name": d.get("name") or d.get("display"),
        "model": (d.get("device_type") or {}).get("model"),
        "manufacturer": ((d.get("device_type") or {}).get("manufacturer") or {}).get("name"),
        "role": (d.get("role") or {}).get("name"),
        "site": (d.get("site") or {}).get("name"),
        "location": (d.get("location") or {}).get("name"),
        "status": (d.get("status") or {}).get("label"),
        "primary_ip": primary,
        "serial": d.get("serial"),
        "platform": (d.get("platform") or {}).get("name"),
        # os_build is the device-side OS version convention; consumed by the
        # halo backend's CVE scanner alongside platform.
        "os_version": _clean_version((d.get("custom_fields") or {}).get("os_build")),
        "tags": [t.get("slug") for t in (d.get("tags") or [])],
        "ips": [ip for ip in [_bare_ip(primary)] if ip],
        # bare IP -> full CIDR; "ips" stays bare because the halo backend
        # keys telemetry matching off bare addresses.
        "cidrs": {_bare_ip(primary): primary} if primary else {},
    }


def _normalize_vm(v: dict) -> dict:
    primary = (v.get("primary_ip4") or v.get("primary_ip6") or {}).get("address")
    return {
        "kind": "vm",
        "id": v.get("id"),
        "host_id": f"vm:{v.get('id')}",
        "name": v.get("name") or v.get("display"),
        "cluster": (v.get("cluster") or {}).get("name"),
        "role": (v.get("role") or {}).get("name"),
        "site": (v.get("site") or {}).get("name"),
        "status": (v.get("status") or {}).get("label"),
        "primary_ip": primary,
        "platform": (v.get("platform") or {}).get("name"),
        "os_version": _clean_version((v.get("custom_fields") or {}).get("os_version")),
        "vcpus": v.get("vcpus"),
        "memory": v.get("memory"),
        "disk": v.get("disk"),
        "tags": [t.get("slug") for t in (v.get("tags") or [])],
        "ips": [ip for ip in [_bare_ip(primary)] if ip],
        "cidrs": {_bare_ip(primary): primary} if primary else {},
    }


def _format_site_address(location: dict) -> str | None:
    parts = [location.get("a_address"), location.get("a_city"),
             location.get("a_state"), location.get("a_postal_code")]
    parts = [p for p in parts if p]
    return ", ".join(parts) if parts else None


async def _resolve_host_location(host: dict, raw: dict, semaphore: asyncio.Semaphore) -> None:
    """Fill host["site"] with a real address from CMD when NetBox only has a
    real location or the generic placeholder site to go on."""
    if host.get("location"):
        return
    if host.get("site") and host["site"] != NETBOX_GENERIC_SITE_NAME:
        return

    slid = (raw.get("custom_fields") or {}).get("cmd_slid")
    if not slid:
        return
    match = CMD_SEGMENT_ID_PATTERN.search(str(slid))
    if not match:
        return
    segment_id = match.group(1)

    async with semaphore:
        cached = await store.get_location(segment_id)
        if cached:
            host["site"] = cached
            return

        try:
            location = await cmd_client.get_location_by_segment(int(segment_id))
        except (httpx.HTTPError, ValueError):
            return
    if not location:
        return
    address = _format_site_address(location)
    if not address:
        return
    await store.set_location(segment_id, address)
    host["site"] = address


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, verify=settings.NETBOX_VERIFY_SSL, **kwargs)


async def fetch_all_hosts() -> list:
    """host = customer-NetBox device or VM (merged, distinguished by "kind").
    Serves the ops/debug GET /inventory/hosts endpoint."""
    async with _client() as client:
        devices = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                                   "/api/dcim/devices/?status=active&limit=0")
        vms = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                               "/api/virtualization/virtual-machines/?status=active&limit=0")
    return [_normalize_device(d) for d in devices] + [_normalize_vm(v) for v in vms]


async def fetch_managed_hosts_from_gtt() -> list:
    """The managed-host record of truth, pulled from the GT-T NetBox.
    Attaches every interface-assigned IP (not just primary) so the backend
    can match telemetry hosts seen on any address."""
    base, token = settings.GTT_NETBOX_URL, settings.GTT_NETBOX_TOKEN
    qp = settings.GTT_NETBOX_QUERY_PARAMS
    ip_qp = "limit=0"
    tenant_id = settings.GTT_NETBOX_TENANT_ID or settings.NETBOX_TENANT_ID
    if tenant_id:
        qp = f"tenant_id={tenant_id}&{qp}"
        # Scopes to IPs tenanted in NetBox; untenanted interface IPs are
        # missed here but primary IPs still arrive via the device records.
        ip_qp = f"tenant_id={tenant_id}&{ip_qp}"
    async with _client() as client:
        devices = await _fetch_all(client, base, token, f"/api/dcim/devices/?{qp}")
        vms = await _fetch_all(client, base, token, f"/api/virtualization/virtual-machines/?{qp}")
        ip_addrs = await _fetch_all(client, base, token, f"/api/ipam/ip-addresses/?{ip_qp}")

    hosts = [_normalize_device(d) for d in devices] + [_normalize_vm(v) for v in vms]
    by_key = {h["host_id"]: h for h in hosts}
    raw_by_key = {f"device:{d.get('id')}": d for d in devices}
    raw_by_key.update({f"vm:{v.get('id')}": v for v in vms})
    for ip in ip_addrs:
        addr = _bare_ip(ip.get("address"))
        if not addr:
            continue
        assigned = ip.get("assigned_object") or {}
        obj_type = ip.get("assigned_object_type")
        if obj_type == "dcim.interface":
            key = f"device:{(assigned.get('device') or {}).get('id')}"
        elif obj_type == "virtualization.vminterface":
            key = f"vm:{(assigned.get('virtual_machine') or {}).get('id')}"
        else:
            continue
        host = by_key.get(key)
        if host:
            if addr not in host["ips"]:
                host["ips"].append(addr)
            host["cidrs"].setdefault(addr, ip["address"])

    semaphore = asyncio.Semaphore(10)
    await asyncio.gather(*(
        _resolve_host_location(h, raw_by_key.get(h["host_id"], {}), semaphore)
        for h in hosts
    ))
    return hosts


def build_indexes(hosts: list) -> tuple[dict, dict]:
    """ip_index: bare IP -> host_id. name_index: lowercased FQDN and
    short name -> host_id (first writer wins on collisions)."""
    ip_index: dict = {}
    name_index: dict = {}
    for h in hosts:
        for ip in h.get("ips", []):
            ip_index.setdefault(ip, h["host_id"])
        name = (h.get("name") or "").strip().lower()
        if name:
            name_index.setdefault(name, h["host_id"])
            short = name.split(".")[0]
            if short:
                name_index.setdefault(short, h["host_id"])
    return ip_index, name_index


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


async def fetch_prefixes_from_customer() -> list:
    """Site prefixes from the customer NetBox, sorted longest-prefix first.
    Site resolution priority mirrors the halo backend: scope > site > tenant."""
    import ipaddress

    async with _client() as client:
        items = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                                 "/api/ipam/prefixes/?limit=0")
    out = []
    for item in items:
        prefix = item.get("prefix")
        if not prefix:
            continue
        src = item.get("scope") or item.get("site") or item.get("tenant") or {}
        name = src.get("name") or src.get("display")
        if not name:
            continue
        try:
            plen = ipaddress.ip_network(prefix, strict=False).prefixlen
        except ValueError:
            continue
        out.append({
            "prefix": prefix,
            "site": src.get("slug") or _slugify(name),
            "site_name": name,
            "_plen": plen,
        })
    out.sort(key=lambda x: x["_plen"], reverse=True)
    for entry in out:
        del entry["_plen"]
    return out
