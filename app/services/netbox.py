import httpx
from app.config import settings

def _headers() -> dict:
    return {"Authorization": f"Token {settings.NETBOX_TOKEN}", "Accept": "application/json"}

def _url(path: str) -> str:
    return f"{settings.NETBOX_URL}{path}"
    
async def _fetch_all(client: httpx.AsyncClient, path: str) -> list:
    """Follow NetBox pagination until exhausted. Raises on HTTP errors."""
    results, url = [], _url(path)
    while url:
        resp = await client.get(url, headers=_headers())
        resp.raise_for_status()
        payload = resp.json()
        results.extend(payload.get("results", []))
        url = payload.get("next")
    return results


async def fetch_all_hosts() -> list:
    """host = NetBox device or VM (merged, distinguished by "kind")."""
    async with httpx.AsyncClient(timeout=30) as client:
        devices = await _fetch_all(client, "/api/dcim/devices/?status=active&limit=0")
        vms = await _fetch_all(client, "/api/virtualization/virtual-machines/?status=active&limit=0")

    hosts = [
        {
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
            "primary_ip": (d.get("primary_ip4") or d.get("primary_ip6") or {}).get("address"),
            "serial": d.get("serial"),
            "platform": (d.get("platform") or {}).get("name"),
            "tags": [t.get("slug") for t in (d.get("tags") or [])],
        }
        for d in devices
    ]
    hosts += [
        {
            "kind": "vm",
            "id": v.get("id"),
            "host_id": f"vm:{v.get('id')}",
            "name": v.get("name") or v.get("display"),
            "cluster": (v.get("cluster") or {}).get("name"),
            "role": (v.get("role") or {}).get("name"),
            "site": (v.get("site") or {}).get("name"),
            "status": (v.get("status") or {}).get("label"),
            "primary_ip": (v.get("primary_ip4") or v.get("primary_ip6") or {}).get("address"),
            "platform": (v.get("platform") or {}).get("name"),
            "vcpus": v.get("vcpus"),
            "memory": v.get("memory"),
            "disk": v.get("disk"),
            "tags": [t.get("slug") for t in (v.get("tags") or [])],
        }
        for v in vms
    ]
    return hosts