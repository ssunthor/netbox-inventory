import time
import httpx
from app.config import settings

GET_SEGMENT_A_SITE_QUERY = """
query GetSegmentASiteInfo($segmentId: Int!) {
  segment(where: {id: {_eq: $segmentId}}) {
    id
    a_address
    a_city
    a_state
    a_postal_code
    a_country_id
    a_country {
      code
      iso3
      name
    }
    a_site_poc
    a_site_phone
    a_site_email
    a_interface
    a_media_type_id
  }
}
"""

GET_SERVICE_ORDER_SITE_IDS_QUERY = """
query GetServiceOrderSiteIds($orderId: Int!) {
  service_order(where: {id: {_eq: $orderId}}) {
    id
    a_site_id
  }
}
"""

GET_CLIENT_SITE_ADDRESS_QUERY = """
query GetClientSiteAddress($siteId: Int!) {
  client_site(where: {id: {_eq: $siteId}}) {
    id
    address1
    city
    state
    postal_code
    country {
      code
    }
  }
}
"""

_access_token = None
_token_expiry_time = 0.0


async def _get_valid_token(client: httpx.AsyncClient) -> str:
    global _access_token, _token_expiry_time
    if _access_token and time.time() < _token_expiry_time:
        return _access_token

    response = await client.post(
        settings.CMD_TOKEN_URL,
        data={"grant_type": "client_credentials", "scope": settings.CMD_SCOPE},
        auth=(settings.CMD_CLIENT_ID, settings.CMD_CLIENT_SECRET),
    )
    response.raise_for_status()
    token_data = response.json()
    _access_token = token_data["access_token"]
    # 60s safety margin, same as cmd_connector's own client.
    _token_expiry_time = time.time() + token_data.get("expires_in", 86400) - 60
    return _access_token

async def ping() -> bool:
    if not settings.CMD_CLIENT_ID or not settings.CMD_CLIENT_SECRET:
        return False
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            return bool(await _get_valid_token(client))
    except httpx.HTTPError:
        return False

async def _gql(client: httpx.AsyncClient, token: str, query: str, variables: dict) -> dict:
    response = await client.post(
        settings.CMD_API_URL,
        json={"query": query, "variables": variables},
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    data = response.json()
    if "errors" in data:
        raise ValueError(f"GraphQL Error: {data['errors'][0]['message']}")
    return data.get("data", {})


async def get_location_by_segment(segment_id: int) -> dict | None:
    if not settings.CMD_CLIENT_ID or not settings.CMD_CLIENT_SECRET:
        return None

    async with httpx.AsyncClient(timeout=30) as client:
        token = await _get_valid_token(client)
        data = await _gql(client, token, GET_SEGMENT_A_SITE_QUERY, {"segmentId": segment_id})

    segments = data.get("segment", [])
    return segments[0] if segments else None


async def get_location_by_gnid(gnid: int) -> dict | None:
    """Two-step lookup: service_order(gnid) → a_site_id → client_site address."""
    if not settings.CMD_CLIENT_ID or not settings.CMD_CLIENT_SECRET:
        return None

    async with httpx.AsyncClient(timeout=30) as client:
        token = await _get_valid_token(client)

        order_data = await _gql(client, token, GET_SERVICE_ORDER_SITE_IDS_QUERY, {"orderId": gnid})
        orders = order_data.get("service_order", [])
        if not orders:
            return None
        a_site_id = orders[0].get("a_site_id")
        if not a_site_id:
            return None

        site_data = await _gql(client, token, GET_CLIENT_SITE_ADDRESS_QUERY, {"siteId": a_site_id})

    sites = site_data.get("client_site", [])
    return sites[0] if sites else None

