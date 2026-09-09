"""Best-effort address -> coordinate resolution for site map plotting.

Most sites here are synthesized from CMD street addresses (_compute_site_name
in netbox.py), so they have no NetBox latitude/longitude of their own. This
module geocodes those addresses through a Nominatim-compatible endpoint and
caches every hit permanently in Redis (inv:geocode - street addresses don't
change). Failures are not cached; the daily sync simply retries them.
"""

import asyncio
import logging

import httpx

from app.config import settings
from app.services import store

logger = logging.getLogger("inventory.geocode")

# Nominatim usage policy: at most 1 request/second, identifying User-Agent.
_REQUEST_GAP_SECONDS = 1.1
_HEADERS = {"User-Agent": "defense-halo-netbox-inventory/1.0"}


async def resolve(addresses: list) -> dict:
    """address -> {"latitude", "longitude"} for every address that resolved,
    from cache or a fresh lookup. Never raises - a geocoder outage just
    yields fewer coordinates."""
    out = {}
    to_fetch = []
    for addr in dict.fromkeys(a for a in addresses if a):
        cached = await store.get_geocode(addr)
        if cached:
            out[addr] = cached
        else:
            to_fetch.append(addr)
    if not to_fetch or not settings.GEOCODE_ENABLED:
        return out

    async with httpx.AsyncClient(timeout=15) as client:
        for i, addr in enumerate(to_fetch):
            if i:
                await asyncio.sleep(_REQUEST_GAP_SECONDS)
            try:
                resp = await client.get(
                    settings.GEOCODE_URL, headers=_HEADERS,
                    params={"q": addr, "format": "jsonv2", "limit": 1})
                resp.raise_for_status()
                results = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("geocode failed for %r: %s", addr, exc)
                continue
            if not results:
                logger.info("geocode: no match for %r", addr)
                continue
            try:
                coords = {"latitude": float(results[0]["lat"]),
                          "longitude": float(results[0]["lon"])}
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            await store.set_geocode(addr, coords)
            out[addr] = coords
    return out
