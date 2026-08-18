"""Write operations against the customer NetBox for auto-registering
discovered hosts. Every helper is idempotent: lookups run before creates,
and ensured object ids are cached in Redis (inv:nbids)."""

import logging
import time

import httpx

from app.config import settings
from app.services import classify, store

logger = logging.getLogger("inventory.netbox_write")

DISCOVERED_ROLE = {"name": "Discovered", "slug": "discovered", "color": "9e9e9e"}
UNKNOWN_MANUFACTURER = {"name": "Unknown", "slug": "unknown"}
UNKNOWN_DEVICE_TYPE = {"model": "Unknown", "slug": "unknown"}
DISCOVERY_TAG = {"name": "halo-discovered", "slug": "halo-discovered", "color": "ff9800"}
UNASSIGNED_SITE = {"name": "Unassigned", "slug": "unassigned", "status": "active"}


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

    # 3. Create the device (PTR name when known, else the IP).
    name = sighting.get("name") or ip
    sources = ",".join(sighting.get("sources") or []) or "telemetry"
    device_payload = {
        "name": name,
        "role": role_id,
        "device_type": type_id,
        "site": site_id,
        "status": "active",
        "tenant": settings.NETBOX_TENANT_ID,
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
                              "tenant": settings.NETBOX_TENANT_ID,
                              "assigned_object_type": "dcim.interface",
                              "assigned_object_id": interface["id"]})
    await _patch(client, f"/api/dcim/devices/{device_id}/",
                 {"primary_ip4": ip_obj["id"]})

    logger.info("registered discovered host %s as device %d (%s)",
                ip, device_id, device_payload["name"])
    return {"device_id": device_id, "name": device_payload["name"]}
