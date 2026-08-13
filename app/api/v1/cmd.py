from fastapi import APIRouter
from app.clients import cmd_client

router = APIRouter()

@router.get("/segment/{segment_id}", summary="Get site from segment")
async def get_segment_a_site_endpoint(segment_id: int):
    result = await cmd_client.get_location_by_segment(segment_id)
    if result is None:
        return {"found": False, "segment_id": segment_id}
    return {"found": True, "segment_id": segment_id, "site": result}
