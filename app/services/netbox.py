import asyncio
import hashlib
import logging
import re

import httpx

from app.clients import cmd_client
from app.config import settings
from app.services import geocode, store

logger = logging.getLogger("inventory.netbox")

# CMD custom field format is "{gnid}-{segment_id}"; segment_id is the trailing int.
CMD_SEGMENT_ID_PATTERN = re.compile(r"-(\d+)$")
# Placeholder site name NetBox falls back to when no real location is set.
NETBOX_GENERIC_SITE_NAME = "CST"


def _headers(token: str) -> dict:
    return {"Authorization": f"Token {token}", "Accept": "application/json"}


def _rebase(next_url: str | None, base_url: str) -> str | None:
    """NetBox behind a TLS-terminating proxy emits http:// pagination links;
    force every "next" URL back onto the configured scheme/host/port."""
    if not next_url:
        return None
    base = httpx.URL(base_url)
    return str(httpx.URL(next_url).copy_with(
        scheme=base.scheme, host=base.host, port=base.port or None))


async def _fetch_all(client: httpx.AsyncClient, base_url: str, token: str, path: str) -> list:
    """Follow NetBox pagination until exhausted. Raises on HTTP errors,
    naming the exact URL that failed."""
    results, url = [], f"{base_url}{path}"
    while url:
        try:
            resp = await client.get(url, headers=_headers(token))
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"NetBox request failed for {url}: {type(exc).__name__}: {exc}") from exc
        resp.raise_for_status()
        payload = resp.json()
        results.extend(payload.get("results", []))
        url = _rebase(payload.get("next"), base_url)
    return results


def _bare_ip(address: str | None) -> str | None:
    return address.split("/")[0] if address else None


def _clean_version(value) -> str | None:
    """Normalize placeholder junk ('None', 'null', 'unknown', empty) to None
    so downstream CVE queries never search for a literal 'FortiOS None'."""
    if value is None:
        return None
    s = str(value).strip()
    return None if not s or s.lower() in ("none", "null", "unknown", "n/a") else s


def _normalize_device(d: dict) -> dict:
    primary = (d.get("primary_ip4") or d.get("primary_ip6") or {}).get("address")
    return {
        "kind": "device",
        "id": d.get("id"),
        "host_id": f"device:{d.get('id')}",
        "name": d.get("name") or d.get("display"),
        "model": (d.get("device_type") or {}).get("model"),
        "manufacturer": ((d.get("device_type") or {}).get("manufacturer") or {}).get("name"),
        "role": (d.get("role") or {}).get("name"),
        "site": (d.get("site") or {}).get("name"),
        "location": (d.get("location") or {}).get("name"),
        "status": (d.get("status") or {}).get("label"),
        "primary_ip": primary,
        "serial": d.get("serial"),
        "platform": (d.get("platform") or {}).get("name"),
        # os_build is the device-side OS version convention; consumed by the
        # halo backend's CVE scanner alongside platform.
        "os_version": _clean_version((d.get("custom_fields") or {}).get("os_build")),
        "tags": [t.get("slug") for t in (d.get("tags") or [])],
        "ips": [ip for ip in [_bare_ip(primary)] if ip],
        # bare IP -> full CIDR; "ips" stays bare because the halo backend
        # keys telemetry matching off bare addresses.
        "cidrs": {_bare_ip(primary): primary} if primary else {},
    }


def _normalize_vm(v: dict) -> dict:
    primary = (v.get("primary_ip4") or v.get("primary_ip6") or {}).get("address")
    return {
        "kind": "vm",
        "id": v.get("id"),
        "host_id": f"vm:{v.get('id')}",
        "name": v.get("name") or v.get("display"),
        "cluster": (v.get("cluster") or {}).get("name"),
        "role": (v.get("role") or {}).get("name"),
        "site": (v.get("site") or {}).get("name"),
        "status": (v.get("status") or {}).get("label"),
        "primary_ip": primary,
        "platform": (v.get("platform") or {}).get("name"),
        "os_version": _clean_version((v.get("custom_fields") or {}).get("os_version")),
        "vcpus": v.get("vcpus"),
        "memory": v.get("memory"),
        "disk": v.get("disk"),
        "tags": [t.get("slug") for t in (v.get("tags") or [])],
        "ips": [ip for ip in [_bare_ip(primary)] if ip],
        "cidrs": {_bare_ip(primary): primary} if primary else {},
    }


def _format_site_address(location: dict) -> str | None:
    parts = [location.get("a_address"), location.get("a_city"),
             location.get("a_state"), location.get("a_postal_code")]
    parts = [p for p in parts if p]
    return ", ".join(parts) if parts else None


async def _resolve_host_location(host: dict, raw: dict, semaphore: asyncio.Semaphore) -> None:
    """Fill host["site"] with a real address from CMD when NetBox only has a
    real location or the generic placeholder site to go on."""
    if host.get("location"):
        return
    if host.get("site") and host["site"] != NETBOX_GENERIC_SITE_NAME:
        return

    slid = (raw.get("custom_fields") or {}).get("cmd_slid")
    if not slid:
        return
    match = CMD_SEGMENT_ID_PATTERN.search(str(slid))
    if not match:
        return
    segment_id = match.group(1)

    async with semaphore:
        cached = await store.get_location(segment_id)
        if cached:
            host["site"] = cached
            return

        try:
            location = await cmd_client.get_location_by_segment(int(segment_id))
        except (httpx.HTTPError, ValueError):
            return
    if not location:
        return
    address = _format_site_address(location)
    if not address:
        return
    await store.set_location(segment_id, address)
    host["site"] = address


def _compute_site_name(address_str: str) -> dict:
    """Derives a stable site_id (hash) and short display_name from a resolved
    CMD address. Neither NetBox nor CMD has a "site" concept of its own -
    port of halo-dev-statrb's netbox_sync_worker.py compute_site()."""
    parts = [p.strip() for p in (address_str or "").split(",")]
    address = parts[0] if len(parts) > 0 else ""
    city = parts[1] if len(parts) > 1 else ""
    state = parts[2] if len(parts) > 2 else ""
    postal = parts[3] if len(parts) > 3 else ""

    normalized = ", ".join(p.lower() for p in [address, city, state, postal] if p)
    normalized = re.sub(r"[^a-z0-9, ]", "", normalized)
    site_id = hashlib.sha256(normalized.encode()).hexdigest()[:16]

    city_abbrev = re.sub(r"[^A-Za-z]", "", city).upper()[:3]
    street_rest = address.split(" ", 1)[1] if " " in address else address
    street_token = re.sub(r"\b(rd|st|ave|blvd|dr|ln)\b", "", street_rest, flags=re.I)
    street_token = re.sub(r"[^A-Za-z]", "", street_token).upper()
    customer_prefix = settings.NETBOX_CUSTOMER_NAME.upper() if settings.NETBOX_CUSTOMER_NAME else "CUSTOMER"
    display_name = f"{customer_prefix}-US-{state}{city_abbrev}-{street_token}"

    return {"site_id": site_id, "display_name": display_name}


def _disambiguate_site_names(items: list) -> None:
    """Appends -{site_id[:6]} (in place) to any display_name shared by more
    than one entry - address-derived names can collide (e.g. two streets
    abbreviating the same way). Only touches names that actually collide."""
    by_name: dict = {}
    for item in items:
        by_name.setdefault(item["display_name"], []).append(item)
    for group in by_name.values():
        if len(group) > 1:
            for item in group:
                item["display_name"] = f"{item['display_name']}-{item['site_id'][:6]}"


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, verify=settings.NETBOX_VERIFY_SSL, **kwargs)


async def fetch_all_hosts() -> list:
    """host = customer-NetBox device or VM (merged, distinguished by "kind").
    Serves the ops/debug GET /inventory/hosts endpoint."""
    async with _client() as client:
        devices = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                                   "/api/dcim/devices/?status=active&limit=0")
        vms = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                               "/api/virtualization/virtual-machines/?status=active&limit=0")
    return [_normalize_device(d) for d in devices] + [_normalize_vm(v) for v in vms]


async def _fetch_ips_by_ids(client: httpx.AsyncClient, base: str, token: str,
                             param_name: str, ids: list, chunk_size: int = 100) -> list:
    """IP-addresses assigned to any of the given device/VM ids, chunked to
    keep query strings reasonable. Filters by id rather than tenant_id -
    an IP's own tenant tag is frequently missing or wrong (tagged to
    "gtt-unsorted" or even a different customer entirely) even when it's
    genuinely assigned to one of our devices, which silently dropped it
    when this filtered on tenant_id directly."""
    results = []
    for i in range(0, len(ids), chunk_size):
        chunk = ids[i:i + chunk_size]
        qs = "&".join(f"{param_name}={id_}" for id_ in chunk)
        results.extend(await _fetch_all(client, base, token, f"/api/ipam/ip-addresses/?{qs}&limit=0"))
    return results


async def fetch_managed_hosts_from_gtt() -> tuple[list, dict]:
    """The managed-host record of truth, pulled from the GT-T NetBox.
    Attaches every interface-assigned IP (not just primary) so the backend
    can match telemetry hosts seen on any address.

    Returns (hosts, site_addresses) where site_addresses maps each computed
    site display name to the CMD street address it was derived from - the
    only geocodable handle those synthetic sites have (see build_sites)."""
    base, token = settings.GTT_NETBOX_URL, settings.GTT_NETBOX_TOKEN
    qp = settings.GTT_NETBOX_QUERY_PARAMS
    tenant_id = settings.GTT_NETBOX_TENANT_ID or settings.NETBOX_TENANT_ID
    if tenant_id:
        qp = f"tenant_id={tenant_id}&{qp}"
    async with _client() as client:
        devices = await _fetch_all(client, base, token, f"/api/dcim/devices/?{qp}")
        vms = await _fetch_all(client, base, token, f"/api/virtualization/virtual-machines/?{qp}")
        ip_addrs = []
        if devices:
            ip_addrs += await _fetch_ips_by_ids(client, base, token, "device_id",
                                                 [d["id"] for d in devices])
        if vms:
            ip_addrs += await _fetch_ips_by_ids(client, base, token, "virtual_machine_id",
                                                 [v["id"] for v in vms])

    hosts = [_normalize_device(d) for d in devices] + [_normalize_vm(v) for v in vms]
    by_key = {h["host_id"]: h for h in hosts}
    raw_by_key = {f"device:{d.get('id')}": d for d in devices}
    raw_by_key.update({f"vm:{v.get('id')}": v for v in vms})
    for ip in ip_addrs:
        addr = _bare_ip(ip.get("address"))
        if not addr:
            continue
        assigned = ip.get("assigned_object") or {}
        obj_type = ip.get("assigned_object_type")
        if obj_type == "dcim.interface":
            key = f"device:{(assigned.get('device') or {}).get('id')}"
        elif obj_type == "virtualization.vminterface":
            key = f"vm:{(assigned.get('virtual_machine') or {}).get('id')}"
        else:
            continue
        host = by_key.get(key)
        if host:
            if addr not in host["ips"]:
                host["ips"].append(addr)
            host["cidrs"].setdefault(addr, ip["address"])

    semaphore = asyncio.Semaphore(10)
    await asyncio.gather(*(
        _resolve_host_location(h, raw_by_key.get(h["host_id"], {}), semaphore)
        for h in hosts
    ))

    # _resolve_host_location writes the raw CMD address (always
    # "addr, city, state, zip") into host["site"] on success; replace it with
    # our short computed name. Disambiguation needs the full batch, so this
    # runs as a second pass after every host is resolved, not inline above.
    computed = [{**_compute_site_name(h["site"]), "host": h, "address": h["site"]}
                for h in hosts if h.get("site") and "," in h["site"]]
    _disambiguate_site_names(computed)
    site_addresses = {}
    for c in computed:
        c["host"]["site"] = c["display_name"]
        site_addresses[c["display_name"]] = c["address"]

    return hosts, site_addresses


def build_indexes(hosts: list) -> tuple[dict, dict]:
    """ip_index: bare IP -> host_id. name_index: lowercased FQDN and
    short name -> host_id (first writer wins on collisions)."""
    ip_index: dict = {}
    name_index: dict = {}
    for h in hosts:
        for ip in h.get("ips", []):
            ip_index.setdefault(ip, h["host_id"])
        name = (h.get("name") or "").strip().lower()
        if name:
            name_index.setdefault(name, h["host_id"])
            short = name.split(".")[0]
            if short:
                name_index.setdefault(short, h["host_id"])
    return ip_index, name_index


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


async def fetch_prefixes_from_customer() -> list:
    """Site prefixes from the customer NetBox, sorted longest-prefix first.
    Site resolution priority mirrors the halo backend: scope > site > tenant."""
    import ipaddress

    async with _client() as client:
        items = await _fetch_all(client, settings.NETBOX_URL, settings.NETBOX_TOKEN,
                                 "/api/ipam/prefixes/?limit=0")
    out = []
    for item in items:
        prefix = item.get("prefix")
        if not prefix:
            continue
        src = item.get("scope") or item.get("site") or item.get("tenant") or {}
        name = src.get("name") or src.get("display")
        if not name:
            continue
        try:
            plen = ipaddress.ip_network(prefix, strict=False).prefixlen
        except ValueError:
            continue
        out.append({
            "prefix": prefix,
            "site": src.get("slug") or slugify(name),
            "site_name": name,
            "_plen": plen,
        })
    out.sort(key=lambda x: x["_plen"], reverse=True)
    for entry in out:
        del entry["_plen"]
    return out


async def build_sites(hosts: list, prefixes: list, site_addresses: dict) -> list:
    """One entry per known site, with best-effort coordinates for the
    dashboard's Destinations map: a real DCIM site record's own
    latitude/longitude wins; otherwise the site's street address (the CMD
    address a computed site was derived from, or the DCIM physical_address)
    is geocoded. Sites with neither stay in the list with null coordinates -
    they still label subnets, they just can't be plotted."""
    sites: dict = {}

    def add(name, slug=None, address=None):
        if not name:
            return
        entry = sites.setdefault(name, {
            "site": slug or slugify(name), "site_name": name,
            "latitude": None, "longitude": None, "address": None,
        })
        if address and not entry["address"]:
            entry["address"] = address

    for h in hosts:
        add(h.get("site"), address=site_addresses.get(h.get("site")))
    for p in prefixes:
        add(p.get("site_name"), slug=p.get("site"))
    for m in await store.get_manual_prefixes():
        add(m.get("site_name"), slug=m.get("site"))

    # Real DCIM site records (either NetBox instance) may carry coordinates,
    # or at least an address worth geocoding.
    for base, token in ((settings.NETBOX_URL, settings.NETBOX_TOKEN),
                        (settings.GTT_NETBOX_URL, settings.GTT_NETBOX_TOKEN)):
        try:
            async with _client() as client:
                records = await _fetch_all(client, base, token, "/api/dcim/sites/?limit=0")
        except Exception as exc:
            logger.warning("DCIM site fetch failed for %s (skipping): %s", base, exc)
            continue
        for rec in records:
            entry = sites.get(rec.get("name"))
            if not entry:
                continue
            if rec.get("latitude") is not None and rec.get("longitude") is not None:
                try:
                    entry["latitude"] = float(rec["latitude"])
                    entry["longitude"] = float(rec["longitude"])
                except (TypeError, ValueError):
                    pass
            elif rec.get("physical_address") and not entry["address"]:
                entry["address"] = rec["physical_address"].replace("\n", ", ")

    pending = [e["address"] for e in sites.values()
               if e["latitude"] is None and e["address"]]
    coords = await geocode.resolve(pending)
    for entry in sites.values():
        if entry["latitude"] is None and entry["address"] in coords:
            entry["latitude"] = coords[entry["address"]]["latitude"]
            entry["longitude"] = coords[entry["address"]]["longitude"]

    return sorted(sites.values(), key=lambda e: e["site_name"].lower())
