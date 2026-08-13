from fastapi import APIRouter
from app.services.netbox import fetch_all_hosts

router = APIRouter()

@router.get("/hosts")
async def get_hosts():
    hosts = await fetch_all_hosts()
    return {
        "hosts": hosts,
        "count": len(hosts)
    }
