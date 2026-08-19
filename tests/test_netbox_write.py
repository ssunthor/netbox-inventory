import json

import httpx
import respx
from httpx import Response

from app.services import netbox_write, store


def _page(results):
    return {"results": results, "next": None}


@respx.mock
async def test_tenant_resolved_by_name_and_cached(fake_redis):
    respx.get("http://netbox.test/api/tenancy/tenants/").mock(
        return_value=Response(200, json=_page([{"id": 5, "slug": "test-corp"}])))

    async with httpx.AsyncClient() as client:
        assert await netbox_write._resolve_tenant_id(client) == 5
        # Second call served from the inv:nbids cache — no extra HTTP.
        respx.reset()
        assert await netbox_write._resolve_tenant_id(client) == 5

    assert await store.get_nbid("tenant:test-corp") == 5


@respx.mock
async def test_tenant_create_retries_with_group_when_required(fake_redis):
    respx.get("http://netbox.test/api/tenancy/tenants/").mock(
        return_value=Response(200, json=_page([])))
    tenant_create = respx.post("http://netbox.test/api/tenancy/tenants/").mock(
        side_effect=[
            Response(400, json={"group": ["This field is required."]}),
            Response(201, json={"id": 6}),
        ])
    respx.get("http://netbox.test/api/tenancy/tenant-groups/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/tenancy/tenant-groups/").mock(
        return_value=Response(201, json={"id": 3}))

    async with httpx.AsyncClient() as client:
        assert await netbox_write._resolve_tenant_id(client) == 6

    first = json.loads(tenant_create.calls[0].request.content)
    assert "group" not in first  # stock instances stay group-free
    retry = json.loads(tenant_create.calls[1].request.content)
    assert retry["group"] == 3 and retry["slug"] == "test-corp"
    assert await store.get_nbid("tenant:test-corp") == 6


@respx.mock
async def test_tenant_create_other_400_still_raises(fake_redis):
    respx.get("http://netbox.test/api/tenancy/tenants/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/tenancy/tenants/").mock(
        return_value=Response(400, json={"name": ["Invalid name."]}))

    async with httpx.AsyncClient() as client:
        try:
            await netbox_write._resolve_tenant_id(client)
        except httpx.HTTPStatusError as exc:
            assert "Invalid name" in str(exc)
        else:
            raise AssertionError("expected HTTPStatusError")
