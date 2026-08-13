from fastapi import APIRouter
from app.services.health import check_all

router = APIRouter()

@router.get("/")
async def health():
    return {
        "status": await check_all()
    }


@router.get("/kafka")
async def kafka_health():
    return {
        "status": "ok"
    }