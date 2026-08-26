"""Write operations against the customer NetBox for auto-registering
discovered hosts. Every helper is idempotent: lookups run before creates,
and ensured object ids are cached in Redis (inv:nbids)."""

import logging
import time

import httpx

from app.config import settings
from app.services import classify, store
from app.services.netbox import _slugify

logger = logging.getLogger("inventory.netbox_write")

DISCOVERED_ROLE = {"name": "Discovered", "slug": "discovered", "color": "9e9e9e"}
UNKNOWN_MANUFACTURER = {"name": "Unknown", "slug": "unknown"}
UNKNOWN_DEVICE_TYPE = {"model": "Unknown", "slug": "unknown"}
DISCOVERY_TAG = {"name": "halo-discovered", "slug": "halo-discovered", "color": "ff9800"}
UNASSIGNED_SITE = {"name": "Unassigned", "slug": "unassigned", "status": "active"}
IMPORTED_ROLE = {"name": "Imported", "slug": "imported", "color": "2196f3"}
IMPORT_TAG = {"name": "customer-imported", "slug": "customer-imported", "color": "2196f3"}


def _headers() -> dict:
    return {"Authorization": f"Token {settings.NETBOX_TOKEN}",
            "Accept": "application/json"}


def _url(path: str) -> str:
    return f"{settings.NETBOX_URL}{path}"


def _check(resp: httpx.Response) -> None:
    """raise_for_status, but with the NetBox error body — which names the
    exact offending field — folded into the exception message."""
    if resp.is_error:
        raise httpx.HTTPStatusError(
            f"{resp.status_code} {resp.reason_phrase} for "
            f"{resp.request.method} {resp.request.url}: {resp.text[:500]}",
            request=resp.request, response=resp)


async def _get_results(client: httpx.AsyncClient, path: str) -> list:
    resp = await client.get(_url(path), headers=_headers())
    _check(resp)
    return resp.json().get("results", [])


async def _post(client: httpx.AsyncClient, path: str, payload: dict) -> dict:
    resp = await client.post(_url(path), headers=_headers(), json=payload)
    _check(resp)
    return resp.json()


async def _patch(client: httpx.AsyncClient, path: str, payload: dict) -> dict:
    resp = await client.patch(_url(path), headers=_headers(), json=payload)
    _check(resp)
    return resp.json()


async def _ensure(client: httpx.AsyncClient, cache_key: str,
                  list_path: str, create_path: str, payload: dict) -> int:
    """Return the id of an object, looking it up (and creating it if absent)
    only on cache miss."""
    cached = await store.get_nbid(cache_key)
    if cached:
        return cached
    results = await _get_results(client, list_path)
    if results:
        nbid = results[0]["id"]
    else:
        nbid = (await _post(client, create_path, payload))["id"]
    await store.set_nbid(cache_key, nbid)
    return nbid


async def _resolve_tenant_id(client: httpx.AsyncClient) -> int:
    """Tenant for objects we write to the customer NetBox, resolved by
    NETBOX_CUSTOMER_NAME (created if absent). Numeric tenant ids don't
    transfer between NetBox instances — NETBOX_TENANT_ID belongs to the
    GT-T instance's scoping and must never be assumed to exist locally."""
    name = settings.NETBOX_CUSTOMER_NAME
    slug = _slugify(name)
    cached = await store.get_nbid(f"tenant:{slug}")
    if cached:
        return cached
    results = await _get_results(client, f"/api/tenancy/tenants/?slug={slug}")
    if results:
        nbid = results[0]["id"]
    else:
        payload = {"name": name, "slug": slug}
        try:
            nbid = (await _post(client, "/api/tenancy/tenants/", payload))["id"]
        except httpx.HTTPStatusError as exc:
            # Stock NetBox leaves tenant.group optional, but some instances
            # enforce it via custom validation — retry under an ensured
            # NETBOX_TENANT_GROUP group only when the instance demands it.
            if exc.response.status_code != 400 or b"group" not in exc.response.content:
                raise
            group_name = settings.NETBOX_TENANT_GROUP
            group_slug = _slugify(group_name)
            group_id = await _ensure(
                client, f"tenantgroup:{group_slug}",
                f"/api/tenancy/tenant-groups/?slug={group_slug}",
                "/api/tenancy/tenant-groups/",
                {"name": group_name, "slug": group_slug})
            nbid = (await _post(client, "/api/tenancy/tenants/",
                                {**payload, "group": group_id}))["id"]
    await store.set_nbid(f"tenant:{slug}", nbid)
    return nbid


async def _resolve_site_id(client: httpx.AsyncClient, ip: str, prefixes: list) -> int:
    match = classify.site_for_ip(ip, prefixes)
    if match:
        slug = match["site"]
        cached = await store.get_nbid(f"site:{slug}")
        if cached:
            return cached
        results = await _get_results(client, f"/api/dcim/sites/?slug={slug}")
        if results:
            await store.set_nbid(f"site:{slug}", results[0]["id"])
            return results[0]["id"]
        logger.warning("prefix matched site slug %r but no such site in customer NetBox; "
                       "falling back to Unassigned", slug)
    return await _ensure(client, "site:unassigned",
                         "/api/dcim/sites/?slug=unassigned",
                         "/api/dcim/sites/", UNASSIGNED_SITE)


async def register_discovered_host(client: httpx.AsyncClient,
                                   sighting: dict, prefixes: list) -> dict:
    """Full creation sequence for one discovered host. Returns
    {device_id, name}. Safe to re-run: an already-assigned IP short-circuits."""
    ip = sighting["ip"]

    # 1. Dedup: if the IP already exists and is assigned, treat as registered.
    existing_ips = await _get_results(client, f"/api/ipam/ip-addresses/?address={ip}")
    ip_obj = existing_ips[0] if existing_ips else None
    if ip_obj and ip_obj.get("assigned_object_id"):
        assigned = ip_obj.get("assigned_object") or {}
        device = assigned.get("device") or assigned.get("virtual_machine") or {}
        return {"device_id": device.get("id"), "name": device.get("name")}

    # 2. Ensure placeholder objects (each cached after first run).
    role_id = await _ensure(client, "role:discovered",
                            "/api/dcim/device-roles/?slug=discovered",
                            "/api/dcim/device-roles/", DISCOVERED_ROLE)
    mfr_id = await _ensure(client, "manufacturer:unknown",
                           "/api/dcim/manufacturers/?slug=unknown",
                           "/api/dcim/manufacturers/", UNKNOWN_MANUFACTURER)
    type_id = await _ensure(client, "devicetype:unknown",
                            "/api/dcim/device-types/?slug=unknown",
                            "/api/dcim/device-types/",
                            {**UNKNOWN_DEVICE_TYPE, "manufacturer": mfr_id})
    # Ensures the tag exists (with our color); assignment below must use the
    # dict form — NetBox's writable tags field rejects bare integer ids.
    await _ensure(client, "tag:halo-discovered",
                  "/api/extras/tags/?slug=halo-discovered",
                  "/api/extras/tags/", DISCOVERY_TAG)
    site_id = await _resolve_site_id(client, ip, prefixes)
    tenant_id = await _resolve_tenant_id(client)

    # 3. Create the device (PTR name when known, else the IP).
    name = sighting.get("name") or ip
    sources = ",".join(sighting.get("sources") or []) or "telemetry"
    device_payload = {
        "name": name,
        "role": role_id,
        "device_type": type_id,
        "site": site_id,
        "status": "active",
        "tenant": tenant_id,
        "tags": [{"name": DISCOVERY_TAG["name"], "slug": DISCOVERY_TAG["slug"]}],
        "comments": (f"Auto-discovered by Defense Halo on "
                     f"{time.strftime('%Y-%m-%d', time.gmtime())}; "
                     f"sightings={sighting.get('count', 0)}; sources={sources}"),
    }
    try:
        device = await _post(client, "/api/dcim/devices/", device_payload)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 400 and b"name" in exc.response.content:
            device_payload["name"] = f"{name}-{ip}"
            device = await _post(client, "/api/dcim/devices/", device_payload)
        else:
            raise
    device_id = device["id"]

    # 4. Interface + IP assignment + primary IP.
    interface = await _post(client, "/api/dcim/interfaces/",
                            {"device": device_id, "name": "eth0", "type": "other"})
    if ip_obj:
        ip_obj = await _patch(client, f"/api/ipam/ip-addresses/{ip_obj['id']}/",
                              {"assigned_object_type": "dcim.interface",
                               "assigned_object_id": interface["id"]})
    else:
        ip_obj = await _post(client, "/api/ipam/ip-addresses/",
                             {"address": f"{ip}/32", "status": "active",
                              "tenant": tenant_id,
                              "assigned_object_type": "dcim.interface",
                              "assigned_object_id": interface["id"]})
    await _patch(client, f"/api/dcim/devices/{device_id}/",
                 {"primary_ip4": ip_obj["id"]})

    logger.info("registered discovered host %s as device %d (%s)",
                ip, device_id, device_payload["name"])
    return {"device_id": device_id, "name": device_payload["name"]}


async def import_customer_host(client: httpx.AsyncClient, row: dict, prefixes: list) -> dict:
    """Create one CSV-import row as a real NetBox device. Mirrors
    register_discovered_host's sequence, but tagged/rated distinctly
    (customer-imported vs halo-discovered) since these come from a manual
    CSV, not telemetry, and the customer may name an explicit site/
    manufacturer/model rather than leaving them to Unknown/Unassigned.
    Returns {"status": "created"|"skipped", ...}. Also records the host in
    store's inv:imported registry so it can be listed/edited/deleted later
    without a live NetBox round-trip."""
    ip = row["ip"]
    name = row["name"]

    existing_ips = await _get_results(client, f"/api/ipam/ip-addresses/?address={ip}")
    ip_obj = existing_ips[0] if existing_ips else None
    if ip_obj and ip_obj.get("assigned_object_id"):
        return {"status": "skipped", "reason": "ip already assigned in NetBox", "ip": ip, "name": name}

    role_name = row.get("role")
    if role_name:
        role_slug = _slugify(role_name)
        role_id = await _ensure(client, f"role:{role_slug}",
                                f"/api/dcim/device-roles/?slug={role_slug}",
                                "/api/dcim/device-roles/",
                                {"name": role_name, "slug": role_slug, "color": IMPORTED_ROLE["color"]})
    else:
        role_id = await _ensure(client, "role:imported",
                                "/api/dcim/device-roles/?slug=imported",
                                "/api/dcim/device-roles/", IMPORTED_ROLE)

    mfr_name = row.get("manufacturer")
    if mfr_name:
        mfr_slug = _slugify(mfr_name)
        mfr_id = await _ensure(client, f"manufacturer:{mfr_slug}",
                               f"/api/dcim/manufacturers/?slug={mfr_slug}",
                               "/api/dcim/manufacturers/", {"name": mfr_name, "slug": mfr_slug})
    else:
        mfr_id = await _ensure(client, "manufacturer:unknown",
                               "/api/dcim/manufacturers/?slug=unknown",
                               "/api/dcim/manufacturers/", UNKNOWN_MANUFACTURER)

    model_name = row.get("model")
    if model_name:
        model_slug = _slugify(model_name)
        type_id = await _ensure(client, f"devicetype:{model_slug}",
                                f"/api/dcim/device-types/?slug={model_slug}",
                                "/api/dcim/device-types/",
                                {"model": model_name, "slug": model_slug, "manufacturer": mfr_id})
    else:
        type_id = await _ensure(client, "devicetype:unknown",
                                "/api/dcim/device-types/?slug=unknown",
                                "/api/dcim/device-types/",
                                {**UNKNOWN_DEVICE_TYPE, "manufacturer": mfr_id})

    await _ensure(client, "tag:customer-imported",
                 "/api/extras/tags/?slug=customer-imported",
                 "/api/extras/tags/", IMPORT_TAG)

    site_name = row.get("site")
    if site_name:
        site_slug = _slugify(site_name)
        site_id = await _ensure(client, f"site:{site_slug}",
                                f"/api/dcim/sites/?slug={site_slug}",
                                "/api/dcim/sites/", {"name": site_name, "slug": site_slug, "status": "active"})
    else:
        site_id = await _resolve_site_id(client, ip, prefixes)
    tenant_id = await _resolve_tenant_id(client)

    device_payload = {
        "name": name,
        "role": role_id,
        "device_type": type_id,
        "site": site_id,
        "status": "active",
        "tenant": tenant_id,
        "tags": [{"name": IMPORT_TAG["name"], "slug": IMPORT_TAG["slug"]}],
        "comments": f"Bulk-imported via CSV on {time.strftime('%Y-%m-%d', time.gmtime())}.",
    }
    try:
        device = await _post(client, "/api/dcim/devices/", device_payload)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 400 and b"name" in exc.response.content:
            device_payload["name"] = f"{name}-{ip}"
            device = await _post(client, "/api/dcim/devices/", device_payload)
        else:
            raise
    device_id = device["id"]

    interface = await _post(client, "/api/dcim/interfaces/",
                            {"device": device_id, "name": "eth0", "type": "other"})
    if ip_obj:
        ip_obj = await _patch(client, f"/api/ipam/ip-addresses/{ip_obj['id']}/",
                              {"assigned_object_type": "dcim.interface",
                               "assigned_object_id": interface["id"]})
    else:
        ip_obj = await _post(client, "/api/ipam/ip-addresses/",
                             {"address": f"{ip}/32", "status": "active",
                              "tenant": tenant_id,
                              "assigned_object_type": "dcim.interface",
                              "assigned_object_id": interface["id"]})
    await _patch(client, f"/api/dcim/devices/{device_id}/", {"primary_ip4": ip_obj["id"]})

    logger.info("imported host %s as device %d (%s)", ip, device_id, device_payload["name"])
    await store.mark_imported(ip, device_id, device_payload["name"], row)
    return {"status": "created", "device_id": device_id, "name": device_payload["name"], "ip": ip}


async def _verify_imported_device(client: httpx.AsyncClient, device_id: int) -> dict:
    """Fetch a device and confirm it carries the customer-imported tag -
    the safety guard so update/delete of "imported" hosts can never touch a
    GTT-managed or auto-discovered device. Raises ValueError if not found or
    not tagged; callers should turn that into a 404."""
    resp = await client.get(_url(f"/api/dcim/devices/{device_id}/"), headers=_headers())
    if resp.status_code == 404:
        raise ValueError(f"device {device_id} not found")
    _check(resp)
    device = resp.json()
    tags = {t.get("slug") for t in (device.get("tags") or [])}
    if IMPORT_TAG["slug"] not in tags:
        raise ValueError(f"device {device_id} is not a customer-imported host")
    return device


async def update_imported_host(client: httpx.AsyncClient, device_id: int, updates: dict) -> dict:
    """Update an existing CSV-imported device's name/site/role/manufacturer/
    model. IP reassignment is out of scope - editing the primary IP would
    mean re-homing the NetBox interface/IP object, more moving parts than
    the fixed CSV columns need for v1."""
    device = await _verify_imported_device(client, device_id)
    patch: dict = {}

    if "name" in updates and updates["name"]:
        patch["name"] = updates["name"]

    if "role" in updates and updates["role"]:
        role_slug = _slugify(updates["role"])
        patch["role"] = await _ensure(client, f"role:{role_slug}",
                                      f"/api/dcim/device-roles/?slug={role_slug}",
                                      "/api/dcim/device-roles/",
                                      {"name": updates["role"], "slug": role_slug, "color": IMPORTED_ROLE["color"]})

    if "site" in updates and updates["site"]:
        site_slug = _slugify(updates["site"])
        patch["site"] = await _ensure(client, f"site:{site_slug}",
                                      f"/api/dcim/sites/?slug={site_slug}",
                                      "/api/dcim/sites/",
                                      {"name": updates["site"], "slug": site_slug, "status": "active"})

    if updates.get("manufacturer") or updates.get("model"):
        current_type = device.get("device_type") or {}
        mfr_name = updates.get("manufacturer") or (current_type.get("manufacturer") or {}).get("name")
        model_name = updates.get("model") or current_type.get("model")
        mfr_slug = _slugify(mfr_name) if mfr_name else "unknown"
        mfr_id = await _ensure(client, f"manufacturer:{mfr_slug}",
                               f"/api/dcim/manufacturers/?slug={mfr_slug}",
                               "/api/dcim/manufacturers/",
                               {"name": mfr_name or "Unknown", "slug": mfr_slug})
        model_slug = _slugify(model_name) if model_name else "unknown"
        patch["device_type"] = await _ensure(client, f"devicetype:{model_slug}",
                                             f"/api/dcim/device-types/?slug={model_slug}",
                                             "/api/dcim/device-types/",
                                             {"model": model_name or "Unknown", "slug": model_slug,
                                              "manufacturer": mfr_id})

    if patch:
        device = await _patch(client, f"/api/dcim/devices/{device_id}/", patch)

    # Keep the local registry in sync so listing doesn't need a live NetBox call.
    old = await store.get_imported_by_device_id(device_id)
    if old:
        ip = old["ip"]
        merged = {**old, **{k: v for k, v in updates.items() if v}, "name": device["name"]}
        await store.mark_imported(ip, device_id, device["name"], merged)

    logger.info("updated imported host device %d", device_id)
    return {"device_id": device_id, "name": device["name"]}


async def overwrite_imported_host(client: httpx.AsyncClient, device_id: int, row: dict) -> dict:
    """CSV-import overwrite path: a row whose IP matched a previously
    imported device updates that device's fields instead of being skipped.
    Delegates the actual patch to update_imported_host - same tag guard,
    same field-by-field update logic, just reshaped into an import result."""
    result = await update_imported_host(client, device_id, row)
    return {"status": "updated", "device_id": device_id, "name": result["name"], "ip": row["ip"]}


async def delete_imported_host(client: httpx.AsyncClient, device_id: int) -> None:
    """Delete a CSV-imported device (and drop it from the local registry).
    Guarded the same way as update: refuses anything not tagged
    customer-imported."""
    await _verify_imported_device(client, device_id)
    resp = await client.delete(_url(f"/api/dcim/devices/{device_id}/"), headers=_headers())
    if resp.status_code not in (204, 404):
        _check(resp)

    old = await store.get_imported_by_device_id(device_id)
    if old:
        await store.delete_imported(old["ip"])
    # Drop any cve-monitoring off-list entry so a future device reusing this
    # id doesn't inherit a stale "off" state.
    await store.set_cve_monitoring([f"imported:{device_id}"], True)
    logger.info("deleted imported host device %d", device_id)


async def delete_discovered_host(client: httpx.AsyncClient, ip: str) -> dict:
    """Delete a learned (telemetry-discovered) host: the auto-registered
    NetBox device when one exists, plus the local sighting/registration
    tracking. Two guards: a GTT-managed IP is refused outright
    (PermissionError -> 409 upstream), and a NetBox device is only ever
    deleted when it still carries the halo-discovered tag - a registration
    record pointing at a re-purposed or manually-retagged device leaves the
    NetBox object alone and only clears our tracking."""
    ip_index = await store.get_ip_index()
    registration = await store.get_registered(ip)
    # mark_registered() adds auto-registered hosts to ip_index too, so the
    # managed test must exclude anything we registered ourselves.
    if ip in ip_index and not registration:
        raise PermissionError(f"{ip} is a GTT-managed host and cannot be deleted")

    deleted_device_id = None
    device_id = (registration or {}).get("device_id")
    if device_id:
        resp = await client.get(_url(f"/api/dcim/devices/{device_id}/"), headers=_headers())
        if resp.status_code != 404:
            _check(resp)
            tags = {t.get("slug") for t in (resp.json().get("tags") or [])}
            if DISCOVERY_TAG["slug"] in tags:
                dresp = await client.delete(
                    _url(f"/api/dcim/devices/{device_id}/"), headers=_headers())
                if dresp.status_code not in (204, 404):
                    _check(dresp)
                deleted_device_id = device_id
            else:
                logger.warning(
                    "registered device %d for %s no longer carries the %s tag; "
                    "leaving the NetBox record in place", device_id, ip,
                    DISCOVERY_TAG["slug"])

    await store.delete_registered(ip)
    await store.delete_sighting(ip)
    logger.info("deleted discovered host %s (netbox device: %s)",
                ip, deleted_device_id or "none")
    return {"ip": ip, "netbox_device_deleted": deleted_device_id}
