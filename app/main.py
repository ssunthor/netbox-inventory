import asyncio
import contextlib
import logging

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.services.netbox_sync import sync_loop
from app.services.promoter import promotion_loop

logging.basicConfig(level=logging.INFO)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    workers = [
        asyncio.create_task(sync_loop()),
        asyncio.create_task(promotion_loop()),
    ]
    yield
    for task in workers:
        task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)


app = FastAPI(title="netbox-inventory", lifespan=lifespan)

app.include_router(api_router, prefix="/api/v1")
