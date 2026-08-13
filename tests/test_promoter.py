import json
import time

import respx
from httpx import Response

from app.config import settings
from app.services import promoter, store


def _page(results):
    return {"results": results, "next": None}


async def _seed_eligible(fake_redis, ip="10.250.47.99"):
    now = time.time()
    await fake_redis.hset(f"inv:sight:{ip}", mapping={
        "count": 10, "first_seen": now - 7200, "last_seen": now,
        "name": "disc-host", "sources": "netflow",
    })
    await fake_redis.set(store.KEY_PREFIXES, json.dumps(
        [{"prefix": "10.250.47.0/27", "site": "lon8", "site_name": "LON8"}]))
    return ip


@respx.mock
async def test_full_registration_sequence(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "DISCOVERY_AUTOCREATE_ENABLED", True)
    ip = await _seed_eligible(fake_redis)

    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([])))
    respx.get("http://netbox.test/api/dcim/device-roles/").mock(
        return_value=Response(200, json=_page([])))
    role_create = respx.post("http://netbox.test/api/dcim/device-roles/").mock(
        return_value=Response(201, json={"id": 11}))
    respx.get("http://netbox.test/api/dcim/manufacturers/").mock(
        return_value=Response(200, json=_page([{"id": 12}])))
    respx.get("http://netbox.test/api/dcim/device-types/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/device-types/").mock(
        return_value=Response(201, json={"id": 13}))
    respx.get("http://netbox.test/api/extras/tags/").mock(
        return_value=Response(200, json=_page([{"id": 14}])))
    respx.get("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 21}])))
    device_create = respx.post("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(201, json={"id": 100}))
    respx.post("http://netbox.test/api/dcim/interfaces/").mock(
        return_value=Response(201, json={"id": 200}))
    ip_create = respx.post("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(201, json={"id": 300}))
    primary_patch = respx.patch("http://netbox.test/api/dcim/devices/100/").mock(
        return_value=Response(200, json={"id": 100}))

    result = await promoter.run_promotion_cycle()
    assert result == {"at": result["at"], "eligible": 1, "created": 1, "failed": 0}

    assert role_create.called
    device_payload = json.loads(device_create.calls[0].request.content)
    assert device_payload["name"] == "disc-host"
    assert device_payload["role"] == 11
    assert device_payload["device_type"] == 13
    assert device_payload["site"] == 21  # prefix-matched site, not Unassigned
    assert device_payload["tenant"] == 1
    assert device_payload["tags"] == [14]

    ip_payload = json.loads(ip_create.calls[0].request.content)
    assert ip_payload["address"] == f"{ip}/32"
    assert ip_payload["assigned_object_id"] == 200
    assert json.loads(primary_patch.calls[0].request.content) == {"primary_ip4": 300}

    # Bookkeeping: registered, sighting gone, ip_index updated
    assert json.loads(await fake_redis.hget(store.KEY_REGISTERED, ip))["device_id"] == 100
    assert not await fake_redis.exists(f"inv:sight:{ip}")
    assert (await store.get_ip_index())[ip] == "device:100"

    # Second cycle: nothing eligible, no further creates
    result = await promoter.run_promotion_cycle()
    assert result["eligible"] == 0 and result["created"] == 0
    assert len(device_create.calls) == 1


@respx.mock
async def test_already_assigned_ip_short_circuits(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "DISCOVERY_AUTOCREATE_ENABLED", True)
    ip = await _seed_eligible(fake_redis)

    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([{
            "id": 300, "assigned_object_id": 200,
            "assigned_object": {"device": {"id": 55, "name": "existing-dev"}},
        }])))
    device_create = respx.post("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(201, json={"id": 999}))

    result = await promoter.run_promotion_cycle()
    assert result["created"] == 1
    assert not device_create.called  # dedup: no new device
    assert json.loads(await fake_redis.hget(store.KEY_REGISTERED, ip))["device_id"] == 55


async def test_autocreate_disabled_reports_only(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "DISCOVERY_AUTOCREATE_ENABLED", False)
    await _seed_eligible(fake_redis)
    result = await promoter.run_promotion_cycle()
    assert result["eligible"] == 1 and result["created"] == 0


@respx.mock
async def test_failure_marks_sighting_and_continues(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "DISCOVERY_AUTOCREATE_ENABLED", True)
    ip = await _seed_eligible(fake_redis)

    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(500, json={"detail": "boom"}))

    result = await promoter.run_promotion_cycle()
    assert result["failed"] == 1 and result["created"] == 0
    entry = await fake_redis.hgetall(f"inv:sight:{ip}")
    assert "500" in entry["last_error"]
    statuses = {e["ip"]: e["status"] for e in await store.list_discovered()}
    assert statuses[ip] == "failed"
