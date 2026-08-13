import httpx

from app.config import settings

from app.clients import cmd_client, redis_client

async def ping_netbox() -> bool:
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            res = await client.get(
                f"{settings.NETBOX_URL}/api/status/",
                headers={"Authorization": f"Token {settings.NETBOX_TOKEN}"},
            )
            return res.status_code == 200
        except httpx.HTTPError:
            return False


CHECKS = {
    "netbox": ping_netbox,
    "cmd": cmd_client.ping,
    "redis": redis_client.ping
}

async def check(name: str) -> str:
    return "ok" if await CHECKS[name]() else "down"

async def check_all() -> dict:
    return {name: await check(name) for name in CHECKS}
