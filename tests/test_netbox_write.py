import json

import httpx
import pytest
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


# ---------------------------------------------------------------------------
# update_imported_host — platform and os_version
# ---------------------------------------------------------------------------

@respx.mock
async def test_update_imported_platform_resolved_as_fk(fake_redis):
    device = {
        "id": 10, "name": "router-01",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ASR1001"},
    }
    respx.get("http://netbox.test/api/dcim/devices/10/").mock(return_value=Response(200, json=device))
    respx.get("http://netbox.test/api/dcim/platforms/").mock(return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/platforms/").mock(return_value=Response(201, json={"id": 55}))
    patch_call = respx.patch("http://netbox.test/api/dcim/devices/10/").mock(
        return_value=Response(200, json={**device, "platform": {"id": 55, "name": "IOS-XE"}}))
    # registered entry so store sync runs
    await store.mark_imported("10.0.0.1", 10, "router-01", {"ip": "10.0.0.1"})

    async with httpx.AsyncClient() as client:
        result = await netbox_write.update_imported_host(client, 10, {"platform": "IOS-XE"})

    assert result["device_id"] == 10
    body = json.loads(patch_call.calls[0].request.content)
    assert body["platform"] == 55


@respx.mock
async def test_update_imported_os_version_writes_custom_field(fake_redis):
    device = {
        "id": 11, "name": "sw-01",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Aruba"}, "model": "CX6300"},
    }
    respx.get("http://netbox.test/api/dcim/devices/11/").mock(return_value=Response(200, json=device))
    patch_call = respx.patch("http://netbox.test/api/dcim/devices/11/").mock(
        return_value=Response(200, json=device))
    await store.mark_imported("10.0.0.2", 11, "sw-01", {"ip": "10.0.0.2"})

    async with httpx.AsyncClient() as client:
        await netbox_write.update_imported_host(client, 11, {"os_version": "10.11.0001"})

    body = json.loads(patch_call.calls[0].request.content)
    assert body["custom_fields"]["os_build"] == "10.11.0001"


# ---------------------------------------------------------------------------
# update_discovered_host
# ---------------------------------------------------------------------------

@respx.mock
async def test_update_discovered_basic(fake_redis):
    device = {
        "id": 20, "name": "10.1.2.3",
        "tags": [{"slug": "halo-discovered"}],
        "device_type": {"manufacturer": {"name": "Unknown"}, "model": "Unknown"},
    }
    respx.get("http://netbox.test/api/dcim/devices/20/").mock(return_value=Response(200, json=device))
    respx.get("http://netbox.test/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/device-roles/").mock(return_value=Response(201, json={"id": 7}))
    patch_call = respx.patch("http://netbox.test/api/dcim/devices/20/").mock(
        return_value=Response(200, json={**device, "name": "host-20"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.update_discovered_host(client, 20, {"name": "host-20", "role": "Router"})

    assert result["name"] == "host-20"
    body = json.loads(patch_call.calls[0].request.content)
    assert body["name"] == "host-20"
    assert body["role"] == 7


@respx.mock
async def test_update_discovered_wrong_tag_rejected(fake_redis):
    device = {
        "id": 21, "name": "managed-host",
        "tags": [{"slug": "halo-managed"}],
    }
    respx.get("http://netbox.test/api/dcim/devices/21/").mock(return_value=Response(200, json=device))

    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="not a halo-discovered host"):
            await netbox_write.update_discovered_host(client, 21, {"name": "x"})


@respx.mock
async def test_update_discovered_not_found(fake_redis):
    respx.get("http://netbox.test/api/dcim/devices/99/").mock(return_value=Response(404))

    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="not found"):
            await netbox_write.update_discovered_host(client, 99, {"name": "x"})


@respx.mock
async def test_update_discovered_platform_and_os_version(fake_redis):
    device = {
        "id": 22, "name": "disc-host",
        "tags": [{"slug": "halo-discovered"}],
        "device_type": {"manufacturer": {"name": "Unknown"}, "model": "Unknown"},
    }
    respx.get("http://netbox.test/api/dcim/devices/22/").mock(return_value=Response(200, json=device))
    respx.get("http://netbox.test/api/dcim/platforms/").mock(return_value=Response(200, json=_page([{"id": 3, "slug": "ios-xe"}])))
    patch_call = respx.patch("http://netbox.test/api/dcim/devices/22/").mock(
        return_value=Response(200, json=device))

    async with httpx.AsyncClient() as client:
        await netbox_write.update_discovered_host(client, 22, {"platform": "IOS-XE", "os_version": "17.3.1"})

    body = json.loads(patch_call.calls[0].request.content)
    assert body["platform"] == 3
    assert body["custom_fields"]["os_build"] == "17.3.1"


# ---------------------------------------------------------------------------
# create_site / update_site
# ---------------------------------------------------------------------------

@respx.mock
async def test_create_site_new(fake_redis):
    respx.get("http://netbox.test/api/extras/tags/").mock(
        return_value=Response(200, json=_page([{"id": 99, "slug": "halo-site"}])))
    respx.get("http://netbox.test/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    post_call = respx.post("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(201, json={"id": 30, "name": "London", "slug": "london"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.create_site(client, {"name": "London", "status": "active"})

    assert result == {"id": 30, "slug": "london", "name": "London", "existed": False}
    body = json.loads(post_call.calls[0].request.content)
    assert body["name"] == "London"
    assert body["slug"] == "london"
    assert body["tags"] == [{"id": 99}]
    assert "tenant" not in body


@respx.mock
async def test_create_site_existing_returns_cached(fake_redis):
    respx.get("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 31, "name": "Paris", "slug": "paris"}])))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.create_site(client, {"name": "Paris"})

    assert result["existed"] is True
    assert result["id"] == 31
    assert await store.get_nbid("site:paris") == 31


@respx.mock
async def test_update_site_patches_status(fake_redis):
    respx.get("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 40, "name": "Berlin", "slug": "berlin"}])))
    patch_call = respx.patch("http://netbox.test/api/dcim/sites/40/").mock(
        return_value=Response(200, json={"id": 40, "name": "Berlin", "slug": "berlin"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.update_site(client, "berlin", {"status": "planned"})

    assert result["id"] == 40
    body = json.loads(patch_call.calls[0].request.content)
    assert body["status"] == "planned"


@respx.mock
async def test_update_site_not_found(fake_redis):
    respx.get("http://netbox.test/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))

    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="not found"):
            await netbox_write.update_site(client, "nonexistent", {"status": "active"})
