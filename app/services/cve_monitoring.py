"""Per-host CVE-monitoring flag, persisted as a NetBox custom field.

The customer NetBox is the record of truth: mirrored managed hosts and
customer-imported devices carry a boolean ``cve_monitoring`` custom field
(absent/null/true = monitored, false = excluded from CVE scans). A Redis
set (inv:cve_monitoring_off) caches the "off" hosts so the managed payload
and imported listing can be stamped without live NetBox calls; every sync
re-reads the field from NetBox so edits made directly in NetBox win.

Toggles via the API write NetBox first, then the cache, then bump the
snapshot version so the halo backend re-polls immediately instead of
waiting a full sync interval.
"""

import logging

import httpx

from app.services import netbox_write, store
from app.services.netbox import _client

logger = logging.getLogger("inventory.cve_monitoring")

CUSTOM_FIELD = {
    "name": "cve_monitoring",
    "label": "CVE Monitoring",
    "type": "boolean",
    "default": True,
    "description": "Include this host in Defense Halo CVE vulnerability scans",
}
OBJECT_TYPES = ["dcim.device", "virtualization.virtualmachine"]

_KIND_PATH = {"device": "/api/dcim/devices/",
              "vm": "/api/virtualization/virtual-machines/"}


async def ensure_custom_field(client: httpx.AsyncClient) -> int:
    """Idempotently create the custom field on devices + VMs (id cached in
    inv:nbids after the first run)."""
    cached = await store.get_nbid("customfield:cve_monitoring")
    if cached:
        return cached
    results = await netbox_write._get_results(
        client, f"/api/extras/custom-fields/?name={CUSTOM_FIELD['name']}")
    if results:
        nbid = results[0]["id"]
    else:
        try:
            nbid = (await netbox_write._post(
                client, "/api/extras/custom-fields/",
                {**CUSTOM_FIELD, "object_types": OBJECT_TYPES}))["id"]
        except httpx.HTTPStatusError as exc:
            # NetBox < 4.0 calls the assignment field content_types.
            if exc.response.status_code != 400:
                raise
            nbid = (await netbox_write._post(
                client, "/api/extras/custom-fields/",
                {**CUSTOM_FIELD, "content_types": OBJECT_TYPES}))["id"]
    await store.set_nbid("customfield:cve_monitoring", nbid)
    return nbid


def _resolve_target(target: dict, mirror: dict) -> tuple[str, str, int]:
    """Resolve one API target to (off_list_key, kind, customer NetBox id).

    Managed targets carry a GTT host_id ("device:12"/"vm:3") that must be
    translated through the mirror map — GTT numeric ids never transfer to
    the customer instance. Imported targets carry the customer NetBox
    device id directly ("device:57" as listed by /inventory/imported).
    Raises ValueError when the target can't be resolved.
    """
    host_id = str(target.get("host_id") or "")
    kind, _, raw_id = host_id.partition(":")
    if kind not in _KIND_PATH or not raw_id:
        raise ValueError(f"malformed host_id {host_id!r}")
    if target.get("source") == "imported":
        return f"imported:{raw_id}", "device", int(raw_id)
    entry = mirror.get(host_id)
    if not entry:
        raise ValueError(f"{host_id} has no customer-NetBox mirror yet")
    return host_id, kind, int(entry["id"])


async def set_hosts(targets: list[dict], enabled: bool) -> dict:
    """Toggle the flag for a batch of hosts. Per-target results; a target
    that fails to resolve or write never blocks the rest."""
    mirror = await store.get_mirror_map()
    results, ok_keys = [], []
    async with _client() as client:
        await ensure_custom_field(client)
        for target in targets:
            host_id = target.get("host_id")
            try:
                key, kind, nbid = _resolve_target(target, mirror)
                await netbox_write._patch(
                    client, f"{_KIND_PATH[kind]}{nbid}/",
                    {"custom_fields": {CUSTOM_FIELD["name"]: enabled}})
                ok_keys.append(key)
                results.append({"host_id": host_id, "status": "ok"})
            except Exception as exc:  # noqa: BLE001 - reported per target
                logger.warning("cve-monitoring toggle failed for %s: %s", host_id, exc)
                results.append({"host_id": host_id, "status": "failed",
                                "reason": str(exc)})
    await store.set_cve_monitoring(ok_keys, enabled)
    if ok_keys:
        await store.bump_version()
    return {"enabled": enabled,
            "updated": len(ok_keys),
            "failed": len(results) - len(ok_keys),
            "results": results}


async def _fetch_off_ids(client: httpx.AsyncClient, kind: str, ids: list[int]) -> set:
    """Customer NetBox ids (of `kind`) whose cve_monitoring field is False."""
    off: set = set()
    for start in range(0, len(ids), 50):
        chunk = ids[start:start + 50]
        qp = "&".join(f"id={i}" for i in chunk)
        for obj in await netbox_write._get_results(
                client, f"{_KIND_PATH[kind]}?{qp}&limit=0"):
            if (obj.get("custom_fields") or {}).get(CUSTOM_FIELD["name"]) is False:
                off.add(obj["id"])
    return off


async def refresh_from_netbox(client: httpx.AsyncClient) -> int:
    """Rebuild the off-list cache from the customer NetBox (called after
    each sync/mirror cycle). Returns the number of monitoring-off hosts."""
    mirror = await store.get_mirror_map()
    by_kind: dict[str, dict[int, str]] = {"device": {}, "vm": {}}
    for host_id, entry in mirror.items():
        kind = host_id.partition(":")[0]
        if kind in by_kind:
            by_kind[kind][int(entry["id"])] = host_id
    for imp in await store.list_imported():
        if imp.get("device_id"):
            by_kind["device"][int(imp["device_id"])] = f"imported:{imp['device_id']}"

    off_keys: set = set()
    for kind, id_map in by_kind.items():
        if not id_map:
            continue
        for nbid in await _fetch_off_ids(client, kind, sorted(id_map)):
            off_keys.add(id_map[nbid])
    await store.replace_cve_monitoring_off(off_keys)
    return len(off_keys)
