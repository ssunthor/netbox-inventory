import asyncio

from fastapi import APIRouter

from app.config import settings
from app.schemas import SightingsRequest, SightingsResponse
from app.services import promoter, store
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
