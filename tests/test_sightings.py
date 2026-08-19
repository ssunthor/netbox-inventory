import json
import time

from app.config import settings
from app.services import store


async def test_sightings_classification(fake_redis):
    await fake_redis.set(store.KEY_IP_INDEX, json.dumps({"10.0.0.5": "device:1"}))
    result = await store.record_sightings([
        {"id": "10.0.0.5", "sources": ["syslog"]},        # managed
        {"id": "10.0.0.99", "sources": ["netflow"]},      # tracked
        {"id": "8.8.8.8"},                                # ignored: public
        {"id": "jsmith"},                                 # ignored: not an IP
        {"id": "fw01.acme.net"},                          # ignored: hostname
    ])
    assert result == {"accepted": 2, "ignored": 3, "managed": 1, "tracked": 1}

    entry = await fake_redis.hgetall("inv:sight:10.0.0.99")
    assert entry["count"] == "1"
    assert await fake_redis.ttl("inv:sight:10.0.0.99") > 0


async def test_threshold_semantics(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "DISCOVERY_MIN_SIGHTINGS", 3)
    monkeypatch.setattr(settings, "DISCOVERY_MIN_DURATION_SECONDS", 600)

    now = time.time()
    for i in range(3):
        await store.record_sightings([{"id": "10.1.1.1", "last_seen": now + i}])

    # 3 sightings but too little elapsed time -> still tracking
    discovered = await store.list_discovered()
    assert discovered[0]["status"] == "tracking"

    # Age the first sighting past the duration threshold -> eligible
    await fake_redis.hset("inv:sight:10.1.1.1", "first_seen", now - 700)
    discovered = await store.list_discovered()
    assert discovered[0]["status"] == "eligible"
    assert [e["ip"] for e in await store.get_eligible_sightings()] == ["10.1.1.1"]

    # Below sighting count -> never eligible regardless of age
    await store.record_sightings([{"id": "10.1.1.2"}])
    await fake_redis.hset("inv:sight:10.1.1.2", "first_seen", now - 7000)
    statuses = {e["ip"]: e["status"] for e in await store.list_discovered()}
    assert statuses["10.1.1.2"] == "tracking"


async def test_registered_hosts_listed_and_skipped(fake_redis):
    await store.mark_registered("10.2.2.2", 512, "disc-host")
    result = await store.record_sightings([{"id": "10.2.2.2"}])
    assert result["managed"] == 1 and result["tracked"] == 0

    discovered = await store.list_discovered()
    reg = next(e for e in discovered if e["ip"] == "10.2.2.2")
    assert reg["status"] == "registered"
    assert reg["netbox_id"] == 512

    # Registration reflected into ip_index immediately (version bumped)
    assert (await store.get_ip_index())["10.2.2.2"] == "device:512"
