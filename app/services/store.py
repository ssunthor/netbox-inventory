"""Redis-backed state for the inventory service.

Key layout (all in this service's own Redis DB — DB 1 in the compose stack,
never shared with the backend's morpheus:* keys in DB 0):

  inv:managed:hosts       string  JSON list of normalized managed hosts
  inv:managed:ip_index    string  JSON {bare_ip: host_id}
  inv:managed:name_index  string  JSON {lowercased name/shortname: host_id}
  inv:prefixes            string  JSON [{prefix, site, site_name}] prefixlen-desc
  inv:prefixes:manual     hash    prefix -> JSON {site, site_name}: user-assigned
                                  subnet->site labels from the dashboard; survives
                                  syncs (inv:prefixes is rebuilt wholesale) and is
                                  merged over it in every served prefix list
  inv:sites               string  JSON [{site, site_name, latitude, longitude,
                                  address}] - known sites with best-effort
                                  coordinates, rebuilt by each sync
  inv:geocode             hash    address -> JSON {latitude, longitude} from the
                                  geocoder (never invalidated - addresses don't
                                  change)
  inv:meta                hash    version, synced_at, last_error, host_count, prefix_count
  inv:sight:{ip}          hash    count, first_seen, last_seen, name, sources, last_error
  inv:registered          hash    ip -> JSON {device_id, name, created_at}
  inv:promote:lock:{ip}   string  SET NX EX lock while a promotion is in flight
  inv:nbids               hash    cache of ensured NetBox object ids (role/type/tag/site)
  inv:mirror              hash    host_id -> JSON {id, fp}: customer-NetBox id and
                                  content fingerprint of each mirrored managed host
  inv:cve_monitoring_off  set     hosts excluded from CVE scanning ("device:12" GTT
                                  host_ids for managed, "imported:{device_id}" for
                                  CSV-imported); cache of the NetBox custom field
  inv:location            hash    cmd gnid -> formatted address from CMD (never
                                  invalidated - addresses don't change)
  inv:imported            hash    ip -> JSON {device_id, name, ip, site, role,
                                  manufacturer, model, created_at}: CSV-imported hosts
"""

import ipaddress
import json
import time

from app.clients.redis_client import redis
from app.config import settings
from app.services import classify

KEY_HOSTS = "inv:managed:hosts"
KEY_IP_INDEX = "inv:managed:ip_index"
KEY_NAME_INDEX = "inv:managed:name_index"
KEY_PREFIXES = "inv:prefixes"
KEY_MANUAL_PREFIXES = "inv:prefixes:manual"
KEY_SITES = "inv:sites"
KEY_GEOCODE = "inv:geocode"
KEY_META = "inv:meta"
KEY_REGISTERED = "inv:registered"
KEY_NBIDS = "inv:nbids"
KEY_MIRROR = "inv:mirror"
KEY_CVE_OFF = "inv:cve_monitoring_off"
KEY_LOCATION = "inv:location"
KEY_IMPORTED = "inv:imported"
SIGHT_PREFIX = "inv:sight:"
LOCK_PREFIX = "inv:promote:lock:"


# --- managed snapshot -------------------------------------------------------

async def save_snapshot(hosts: list, ip_index: dict, name_index: dict, prefixes: list) -> int:
    pipe = redis.pipeline()
    pipe.set(KEY_HOSTS, json.dumps(hosts))
    pipe.set(KEY_IP_INDEX, json.dumps(ip_index))
    pipe.set(KEY_NAME_INDEX, json.dumps(name_index))
    pipe.set(KEY_PREFIXES, json.dumps(prefixes))
    pipe.hincrby(KEY_META, "version", 1)
    pipe.hset(KEY_META, mapping={
        "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_error": "",
        "host_count": len(hosts),
        "prefix_count": len(prefixes),
    })
    results = await pipe.execute()
    return int(results[4])  # new version from hincrby


async def record_sync_failure(error: str) -> None:
    await redis.hset(KEY_META, mapping={"last_error": error[:500]})


async def get_meta() -> dict:
    meta = await redis.hgetall(KEY_META)
    return {
        "version": int(meta.get("version", 0)),
        "synced_at": meta.get("synced_at") or None,
        "last_error": meta.get("last_error") or None,
        "stale": bool(meta.get("last_error")),
        "host_count": int(meta.get("host_count", 0)),
        "prefix_count": int(meta.get("prefix_count", 0)),
    }


async def _get_json(key: str, default):
    raw = await redis.get(key)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


async def get_managed_payload() -> dict:
    meta = await get_meta()
    hosts = await _get_json(KEY_HOSTS, [])
    off = await get_cve_monitoring_off()
    for h in hosts:
        h["cve_monitoring"] = h.get("host_id") not in off
    return {
        "version": meta["version"],
        "synced_at": meta["synced_at"],
        "stale": meta["stale"],
        "count": meta["host_count"],
        "hosts": hosts,
        "ip_index": await _get_json(KEY_IP_INDEX, {}),
        "name_index": await _get_json(KEY_NAME_INDEX, {}),
        "prefixes": await get_prefixes(),
        "sites": await get_sites(),
    }


async def get_prefixes() -> list:
    """Synced NetBox prefixes overlaid with the manual subnet->site labels
    (a manual label wins on the same prefix), longest-prefix-first."""
    merged = {p["prefix"]: p for p in await _get_json(KEY_PREFIXES, [])}
    for entry in await get_manual_prefixes():
        merged[entry["prefix"]] = entry

    def _plen(entry):
        try:
            return ipaddress.ip_network(entry["prefix"], strict=False).prefixlen
        except (KeyError, ValueError):
            return -1

    return sorted(merged.values(), key=_plen, reverse=True)


async def get_ip_index() -> dict:
    return await _get_json(KEY_IP_INDEX, {})


# --- manual subnet -> site labels --------------------------------------------

async def get_manual_prefixes() -> list:
    raw = await redis.hgetall(KEY_MANUAL_PREFIXES)
    out = []
    for prefix, val in raw.items():
        try:
            info = json.loads(val)
        except (ValueError, TypeError):
            continue
        out.append({"prefix": prefix, "site": info.get("site"),
                    "site_name": info.get("site_name"), "manual": True})
    return out


async def set_manual_prefixes(entries: list) -> None:
    """Upsert user subnet->site assignments ({prefix, site, site_name} each);
    bumps the snapshot version so the backend's since_version poll re-pulls
    the merged prefix list immediately."""
    if not entries:
        return
    mapping = {e["prefix"]: json.dumps({"site": e["site"], "site_name": e["site_name"]})
               for e in entries}
    await redis.hset(KEY_MANUAL_PREFIXES, mapping=mapping)
    await bump_version()


async def delete_manual_prefix(prefix: str) -> bool:
    removed = await redis.hdel(KEY_MANUAL_PREFIXES, prefix)
    if removed:
        await bump_version()
    return bool(removed)


# --- known sites (for the dashboard's site dropdown / map plotting) ----------

async def get_sites() -> list:
    return await _get_json(KEY_SITES, [])


async def save_sites(sites: list) -> None:
    await redis.set(KEY_SITES, json.dumps(sites))


async def get_geocode(address: str) -> dict | None:
    raw = await redis.hget(KEY_GEOCODE, address)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


async def set_geocode(address: str, coords: dict) -> None:
    await redis.hset(KEY_GEOCODE, address, json.dumps(coords))


# --- sightings --------------------------------------------------------------

async def record_sightings(sightings: list[dict]) -> dict:
    """One sighting = one reporter tick in which the host was active."""
    ip_index = await get_ip_index()
    registered = await redis.hgetall(KEY_REGISTERED)
    now = time.time()
    accepted = ignored = managed = tracked = 0

    for s in sightings:
        ip = (s.get("id") or "").strip()
        if not classify.is_private_ipv4(ip):
            ignored += 1
            continue
        accepted += 1
        if ip in ip_index or ip in registered:
            managed += 1
            continue
        tracked += 1
        key = f"{SIGHT_PREFIX}{ip}"
        pipe = redis.pipeline()
        pipe.hincrby(key, "count", 1)
        pipe.hsetnx(key, "first_seen", now)
        mapping = {"last_seen": s.get("last_seen") or now}
        if s.get("name") and s["name"] != ip:
            mapping["name"] = s["name"]
        if s.get("sources"):
            mapping["sources"] = ",".join(sorted(set(s["sources"])))
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, settings.DISCOVERY_SIGHTING_TTL)
        await pipe.execute()

    return {"accepted": accepted, "ignored": ignored, "managed": managed, "tracked": tracked}


def _is_eligible(entry: dict) -> bool:
    try:
        count = int(entry.get("count", 0))
        first = float(entry.get("first_seen", 0))
        last = float(entry.get("last_seen", 0))
    except (TypeError, ValueError):
        return False
    return (count >= settings.DISCOVERY_MIN_SIGHTINGS
            and last - first >= settings.DISCOVERY_MIN_DURATION_SECONDS)


async def list_discovered() -> list[dict]:
    out = []
    async for key in redis.scan_iter(match=f"{SIGHT_PREFIX}*", count=500):
        ip = key[len(SIGHT_PREFIX):]
        entry = await redis.hgetall(key)
        if not entry:
            continue
        status = "tracking"
        if entry.get("last_error"):
            status = "failed"
        elif _is_eligible(entry):
            status = "eligible"
        out.append({
            "ip": ip,
            "name": entry.get("name") or None,
            "count": int(entry.get("count", 0)),
            "first_seen": float(entry.get("first_seen", 0)),
            "last_seen": float(entry.get("last_seen", 0)),
            "sources": (entry.get("sources") or "").split(",") if entry.get("sources") else [],
            "status": status,
            "last_error": entry.get("last_error") or None,
        })
    registered = await redis.hgetall(KEY_REGISTERED)
    for ip, raw in registered.items():
        try:
            info = json.loads(raw)
        except (ValueError, TypeError):
            info = {}
        out.append({
            "ip": ip,
            "name": info.get("name"),
            "status": "registered",
            "netbox_id": info.get("device_id"),
            "registered_at": info.get("created_at"),
        })
    out.sort(key=lambda e: e.get("last_seen") or 0, reverse=True)
    return out


async def get_eligible_sightings() -> list[dict]:
    return [e for e in await list_discovered()
            if e["status"] == "eligible"]


# --- promotion bookkeeping --------------------------------------------------

async def acquire_promote_lock(ip: str) -> bool:
    return bool(await redis.set(f"{LOCK_PREFIX}{ip}", "1", nx=True, ex=600))


async def release_promote_lock(ip: str) -> None:
    await redis.delete(f"{LOCK_PREFIX}{ip}")


async def mark_registered(ip: str, device_id: int | None, name: str | None) -> None:
    info = {"device_id": device_id, "name": name,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pipe = redis.pipeline()
    pipe.hset(KEY_REGISTERED, ip, json.dumps(info))
    pipe.delete(f"{SIGHT_PREFIX}{ip}")
    # Reflect the registration immediately instead of waiting for the next
    # GTT sync so the backend classifies the host as managed on its next poll.
    await pipe.execute()
    ip_index = await get_ip_index()
    if ip not in ip_index:
        ip_index[ip] = f"device:{device_id}" if device_id else "device:unknown"
        await redis.set(KEY_IP_INDEX, json.dumps(ip_index))
        await redis.hincrby(KEY_META, "version", 1)


async def mark_promotion_failed(ip: str, error: str) -> None:
    key = f"{SIGHT_PREFIX}{ip}"
    if await redis.exists(key):
        await redis.hset(key, "last_error", error[:300])


async def get_registered(ip: str) -> dict | None:
    raw = await redis.hget(KEY_REGISTERED, ip)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


async def delete_registered(ip: str) -> None:
    """Forget an auto-registered host. mark_registered added the IP to the
    shared ip_index (so the backend stamps it managed); that entry must go
    too, or the deleted host would still classify as managed until the next
    GTT sync rebuilds the index."""
    await redis.hdel(KEY_REGISTERED, ip)
    ip_index = await get_ip_index()
    if ip in ip_index:
        del ip_index[ip]
        await redis.set(KEY_IP_INDEX, json.dumps(ip_index))
        await redis.hincrby(KEY_META, "version", 1)


async def delete_sighting(ip: str) -> None:
    await redis.delete(f"{SIGHT_PREFIX}{ip}")


# --- CSV-imported host bookkeeping -------------------------------------------

async def mark_imported(ip: str, device_id: int | None, name: str, row: dict) -> None:
    """Record one CSV-imported host, keyed by ip. Deliberately does NOT touch
    ip_index/KEY_META (unlike mark_registered) - imported hosts are a
    separate category from GTT-managed, not a subset of it, so they must
    stay out of the shared ip_index reconcile_inventory_stamps() uses to
    stamp topology nodes "managed" - otherwise a formerly-silent imported
    host that starts sending telemetry would get mislabeled Managed instead
    of Imported. inv:imported itself (checked by is_ip_imported) is the
    dedup source for re-imports instead."""
    info = {
        "device_id": device_id, "name": name, "ip": ip,
        "site": row.get("site"), "role": row.get("role"),
        "manufacturer": row.get("manufacturer"), "model": row.get("model"),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    await redis.hset(KEY_IMPORTED, ip, json.dumps(info))


async def is_ip_imported(ip: str) -> bool:
    return bool(await redis.hexists(KEY_IMPORTED, ip))


async def list_imported() -> list[dict]:
    raw = await redis.hgetall(KEY_IMPORTED)
    out = []
    for ip, val in raw.items():
        try:
            out.append(json.loads(val))
        except (ValueError, TypeError):
            continue
    out.sort(key=lambda e: e.get("created_at") or "", reverse=True)
    return out


async def get_imported_by_device_id(device_id: int) -> dict | None:
    for entry in await list_imported():
        if entry.get("device_id") == device_id:
            return entry
    return None


async def delete_imported(ip: str) -> None:
    await redis.hdel(KEY_IMPORTED, ip)


async def registered_count() -> int:
    return await redis.hlen(KEY_REGISTERED)


# --- customer-NetBox mirror bookkeeping --------------------------------------

async def get_mirror_map() -> dict:
    """host_id -> {"id": customer NetBox id, "fp": content fingerprint}."""
    raw = await redis.hgetall(KEY_MIRROR)
    out = {}
    for host_id, val in raw.items():
        try:
            out[host_id] = json.loads(val)
        except (ValueError, TypeError):
            continue
    return out


async def set_mirror_entry(host_id: str, nbid: int, fp: str) -> None:
    await redis.hset(KEY_MIRROR, host_id, json.dumps({"id": nbid, "fp": fp}))


async def delete_mirror_entry(host_id: str) -> None:
    await redis.hdel(KEY_MIRROR, host_id)


# --- CVE-monitoring flag cache ----------------------------------------------
# Off-list entries are namespaced to avoid id collisions between the two
# categories: managed hosts use their GTT host_id ("device:12" / "vm:3"),
# CSV-imported hosts use "imported:{customer NetBox device id}".


async def get_cve_monitoring_off() -> set:
    return set(await redis.smembers(KEY_CVE_OFF))


async def set_cve_monitoring(keys: list[str], enabled: bool) -> None:
    if not keys:
        return
    if enabled:
        await redis.srem(KEY_CVE_OFF, *keys)
    else:
        await redis.sadd(KEY_CVE_OFF, *keys)


async def replace_cve_monitoring_off(keys: set) -> None:
    """Atomic rebuild from a NetBox re-read (NetBox is the record of truth;
    out-of-band edits made directly in NetBox win at every sync)."""
    pipe = redis.pipeline()
    pipe.delete(KEY_CVE_OFF)
    if keys:
        pipe.sadd(KEY_CVE_OFF, *keys)
    await pipe.execute()


async def bump_version() -> int:
    """Invalidate the managed-snapshot version so the backend's
    since_version poll sees a change on its next cycle."""
    return int(await redis.hincrby(KEY_META, "version", 1))


# --- NetBox object-id cache -------------------------------------------------

async def get_nbid(cache_key: str) -> int | None:
    val = await redis.hget(KEY_NBIDS, cache_key)
    return int(val) if val else None


async def set_nbid(cache_key: str, nbid: int) -> None:
    await redis.hset(KEY_NBIDS, cache_key, nbid)


# --- CMD location cache ------------------------------------------------------

async def get_location(gnid: str) -> str | None:
    return await redis.hget(KEY_LOCATION, gnid)


async def set_location(gnid: str, address: str) -> None:
    await redis.hset(KEY_LOCATION, gnid, address)
