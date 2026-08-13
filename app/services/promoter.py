import asyncio
import logging
import time

import httpx

from app.config import settings
from app.services import netbox_write, store

logger = logging.getLogger("inventory.promoter")

# Introspection for GET /inventory/status; updated each cycle.
last_run: dict = {"at": None, "eligible": 0, "created": 0, "failed": 0}


async def run_promotion_cycle() -> dict:
    eligible = await store.get_eligible_sightings()
    result = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "eligible": len(eligible), "created": 0, "failed": 0}

    if settings.DISCOVERY_AUTOCREATE_ENABLED and eligible:
        prefixes = await store.get_prefixes()
        async with httpx.AsyncClient(timeout=30) as client:
            for sighting in eligible:
                if result["created"] >= settings.DISCOVERY_MAX_CREATES_PER_RUN:
                    logger.info("create cap (%d) reached; %d eligible deferred to next cycle",
                                settings.DISCOVERY_MAX_CREATES_PER_RUN,
                                len(eligible) - result["created"] - result["failed"])
                    break
                ip = sighting["ip"]
                if not await store.acquire_promote_lock(ip):
                    continue
                try:
                    created = await netbox_write.register_discovered_host(
                        client, sighting, prefixes)
                    await store.mark_registered(ip, created.get("device_id"),
                                                created.get("name"))
                    result["created"] += 1
                except Exception as exc:
                    logger.exception("promotion failed for %s", ip)
                    await store.mark_promotion_failed(ip, str(exc))
                    result["failed"] += 1
                finally:
                    await store.release_promote_lock(ip)

    last_run.clear()
    last_run.update(result)
    return result


async def promotion_loop() -> None:
    while True:
        await asyncio.sleep(settings.DISCOVERY_PROMOTE_INTERVAL)
        try:
            await run_promotion_cycle()
        except Exception:
            logger.exception("promotion cycle crashed")
