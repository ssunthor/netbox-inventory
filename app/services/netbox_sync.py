import asyncio
import logging

from app.config import settings
from app.services import cve_monitoring, netbox, netbox_mirror, netbox_write, store

logger = logging.getLogger("inventory.sync")

STARTUP_RETRIES = 3
STARTUP_RETRY_DELAY = 30


async def run_sync() -> dict:
    """One full sync: managed hosts from the GT-T NetBox, site prefixes from
    the customer NetBox, then an atomic swap of the Redis snapshot.
    On any failure the last-good snapshot is left untouched."""
    try:
        hosts, site_addresses = await netbox.fetch_managed_hosts_from_gtt()
        # IPAM prefixes first (they win on the same CIDR), then each managed
        # host's own network labelled with its site - see netbox.host_networks.
        prefixes = netbox.merge_prefixes(await netbox.fetch_prefixes_from_customer(),
                                         netbox.host_networks(hosts))
        ip_index, name_index = netbox.build_indexes(hosts)
        version = await store.save_snapshot(hosts, ip_index, name_index, prefixes)
        logger.info("sync ok: %d hosts, %d prefixes, version %d",
                    len(hosts), len(prefixes), version)
        result = {"ok": True, "version": version,
                  "host_count": len(hosts), "prefix_count": len(prefixes)}
        try:
            # Site list (with best-effort coordinates) for the dashboard's
            # subnet-labelling UI; never fails the sync - the snapshot is
            # already saved and the last-good site list stays served.
            sites = await netbox.build_sites(hosts, prefixes, site_addresses)
            await store.save_sites(sites)
            result["site_count"] = len(sites)
            if settings.MIRROR_ENABLED:
                sites_with_address = [s for s in sites if s.get("address")]
                upserted = failed = 0
                async with netbox._client() as client:
                    for s in sites_with_address:
                        try:
                            await netbox_write.upsert_gtt_site(
                                client, s["site_name"], s["site"], s["address"])
                            upserted += 1
                        except Exception as exc:
                            logger.warning("upsert_gtt_site %r failed: %s", s["site_name"], exc)
                            failed += 1
                result["gtt_sites_upserted"] = upserted
                if failed:
                    result["gtt_sites_failed"] = failed
        except Exception as exc:
            logger.warning("site build failed (keeping cached sites): %s", exc)
        if settings.MIRROR_ENABLED:
            # Snapshot is already saved — mirror failures are reported in
            # the result but never fail the sync.
            result["mirror"] = await netbox_mirror.mirror_managed_hosts(hosts)
        try:
            # NetBox is the record of truth for the cve_monitoring flag;
            # re-reading it here lets edits made directly in NetBox win.
            async with netbox._client() as client:
                result["cve_monitoring_off"] = await cve_monitoring.refresh_from_netbox(client)
        except Exception as exc:
            logger.warning("cve_monitoring refresh failed (keeping cached off-list): %s", exc)
        return result
    except Exception as exc:
        logger.exception("sync failed")
        await store.record_sync_failure(str(exc))
        return {"ok": False, "error": str(exc)}


async def sync_loop() -> None:
    """Startup sync with retries (a NetBox blip must not leave an empty
    store), then steady-state on NETBOX_SYNC_INTERVAL."""
    for attempt in range(STARTUP_RETRIES):
        result = await run_sync()
        if result["ok"]:
            break
        if attempt < STARTUP_RETRIES - 1:
            await asyncio.sleep(STARTUP_RETRY_DELAY)
    while True:
        await asyncio.sleep(settings.NETBOX_SYNC_INTERVAL)
        await run_sync()
