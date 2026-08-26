import json

import httpx
import pytest
import respx
from httpx import Response

from app.services import netbox_write, store


DEVICE_URL = "http://netbox.test/api/dcim/devices/42/"


async def _seed_registered(fake_redis, ip="10.0.0.9", device_id=42):
    await store.mark_registered(ip, device_id, "host-a")
    return ip


@respx.mock
async def test_managed_ip_is_refused(fake_redis):
    await fake_redis.set("inv:managed:ip_index", json.dumps({"10.0.0.5": "device:1"}))
    async with httpx.AsyncClient() as client:
        with pytest.raises(PermissionError):
            await netbox_write.delete_discovered_host(client, "10.0.0.5")


@respx.mock
async def test_registered_host_deletes_tagged_device_and_tracking(fake_redis):
    ip = await _seed_registered(fake_redis)
    # mark_registered put the ip into ip_index; delete must still proceed.
    assert ip in await store.get_ip_index()
    respx.get(DEVICE_URL).mock(return_value=Response(200, json={
        "id": 42, "tags": [{"slug": "halo-discovered"}]}))
    delete_route = respx.delete(DEVICE_URL).mock(return_value=Response(204))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.delete_discovered_host(client, ip)

    assert delete_route.called
    assert result["netbox_device_deleted"] == 42
    assert await store.get_registered(ip) is None
    assert ip not in await store.get_ip_index()


@respx.mock
async def test_untagged_device_is_left_in_netbox(fake_redis):
    ip = await _seed_registered(fake_redis)
    respx.get(DEVICE_URL).mock(return_value=Response(200, json={
        "id": 42, "tags": [{"slug": "halo-managed"}]}))
    delete_route = respx.delete(DEVICE_URL).mock(return_value=Response(204))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.delete_discovered_host(client, ip)

    assert not delete_route.called
    assert result["netbox_device_deleted"] is None
    # Local tracking is still cleared either way.
    assert await store.get_registered(ip) is None


@respx.mock
async def test_sighting_only_host_clears_tracking_without_netbox(fake_redis):
    ip = "10.0.0.77"
    await store.record_sightings([{"id": ip, "name": None, "sources": [], "last_seen": 1.0}])
    assert await fake_redis.exists(f"inv:sight:{ip}")

    async with httpx.AsyncClient() as client:
        result = await netbox_write.delete_discovered_host(client, ip)

    assert result["netbox_device_deleted"] is None
    assert not await fake_redis.exists(f"inv:sight:{ip}")
