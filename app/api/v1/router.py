from fastapi import APIRouter

from app.api.v1 import health, inventory, cmd

api_router = APIRouter()

api_router.include_router(inventory.router, prefix="/inventory", tags=["Inventory"])
api_router.include_router(health.router, prefix="/health", tags=["Health Check"])
api_router.include_router(cmd.router, prefix="/cmd", tags=["CMD"])