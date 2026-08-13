from redis import asyncio as aioredis
from redis.exceptions import RedisError

from app.config import settings

redis = aioredis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

async def ping() -> bool:
    try:
        return await redis.ping()
    except RedisError:
        return False
