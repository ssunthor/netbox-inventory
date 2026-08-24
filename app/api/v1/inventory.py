import asyncio

import httpx
from fastapi import APIRouter, HTTPException

from app.config import settings
from app.schemas import (ImportedHostUpdate, ImportRequest, ImportResponse,
                         SightingsRequest, SightingsResponse)
from app.services import netbox_mirror, netbox_write, promoter, store
from app.services.netbox import fetch_all_hosts
from app.services.netbox_sync import run_sync

router = APIRouter()


@router.get("/hosts")
async def get_hosts():
    """Live view of the customer NetBox (ops/debug; not the managed record)."""
    hosts = await fetch_all_hosts()
    return {
        "hosts": hosts,
        "count": len(hosts)
    }


@router.get("/managed")
async def get_managed(since_version: int = 0):
    """The managed-host snapshot the halo backend polls. Served entirely
    from Redis; `since_version` short-circuits unchanged polls."""
    meta = await store.get_meta()
    if since_version and since_version == meta["version"]:
        return {"version": meta["version"], "unchanged": True}
    return await store.get_managed_payload()


@router.post("/sightings", response_model=SightingsResponse)
async def post_sightings(body: SightingsRequest):
    """Batched telemetry sightings from the backend. Fire-and-forget
    semantics: non-private ids are counted as ignored, never an error."""
    return await store.record_sightings([s.model_dump() for s in body.sightings])


@router.get("/discovered")
async def get_discovered():
    discovered = await store.list_discovered()
    return {"count": len(discovered), "discovered": discovered}


@router.get("/status")
async def get_status():
    meta = await store.get_meta()
    return {
        "sync": meta,
        "mirror": {
            "enabled": settings.MIRROR_ENABLED,
            "last_run": netbox_mirror.last_run,
        },
        "promoter": {
            "autocreate_enabled": settings.DISCOVERY_AUTOCREATE_ENABLED,
            "min_sightings": settings.DISCOVERY_MIN_SIGHTINGS,
            "min_duration_seconds": settings.DISCOVERY_MIN_DURATION_SECONDS,
            "registered_count": await store.registered_count(),
            "last_run": promoter.last_run,
        },
    }


@router.post("/sync", status_code=202)
async def trigger_sync():
    asyncio.get_running_loop().create_task(run_sync())
    return {"status": "sync scheduled"}


@router.post("/import", response_model=ImportResponse)
async def import_hosts(body: ImportRequest):
    """Bulk-create customer-provided hosts (parsed/validated by the backend
    from a CSV) as real NetBox devices, tagged customer-imported. Dedupes
    against both the GTT-managed set and previously-imported hosts before
    touching NetBox."""
    ip_index = await store.get_ip_index()
    imported_ips = {h["ip"] for h in await store.list_imported()}
    prefixes = await store.get_prefixes()
    seen_ips = set()
    results = []
    created = skipped = failed = 0

    async with httpx.AsyncClient(timeout=30, verify=settings.NETBOX_VERIFY_SSL) as client:
        for row in body.rows:
            row_dict = row.model_dump()
            ip = row_dict["ip"]
            if ip in seen_ips:
                results.append({"status": "skipped", "reason": "duplicate ip in request", "ip": ip, "name": row_dict["name"]})
                skipped += 1
                continue
            seen_ips.add(ip)
            if ip in ip_index:
                results.append({"status": "skipped", "reason": "already managed", "ip": ip, "name": row_dict["name"]})
                skipped += 1
                continue
            if ip in imported_ips:
                results.append({"status": "skipped", "reason": "already imported", "ip": ip, "name": row_dict["name"]})
                skipped += 1
                continue
            try:
                result = await netbox_write.import_customer_host(client, row_dict, prefixes)
                results.append(result)
                if result["status"] == "created":
                    created += 1
                else:
                    skipped += 1
            except Exception as e:
                results.append({"status": "failed", "reason": str(e), "ip": ip, "name": row_dict["name"]})
                failed += 1

    return {"total": len(body.rows), "created": created, "skipped": skipped, "failed": failed, "results": results}


@router.get("/imported")
async def get_imported():
    """CSV-imported hosts, served from the local registry (no live NetBox
    call needed)."""
    imported = await store.list_imported()
    return {"count": len(imported), "imported": imported}


@router.patch("/imported/{device_id}")
async def patch_imported(device_id: int, body: ImportedHostUpdate):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    async with httpx.AsyncClient(timeout=30, verify=settings.NETBOX_VERIFY_SSL) as client:
        try:
            return await netbox_write.update_imported_host(client, device_id, updates)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))


@router.delete("/imported/{device_id}", status_code=204)
async def delete_imported(device_id: int):
    async with httpx.AsyncClient(timeout=30, verify=settings.NETBOX_VERIFY_SSL) as client:
        try:
            await netbox_write.delete_imported_host(client, device_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
