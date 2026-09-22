"""API-layer tests for read-only inventory endpoints:
  GET /hosts
  GET /managed
  GET /discovered
  GET /imported
  GET /status
"""
import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app
from app.services import store

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _nb_device(device_id=1, name="host-a", ip="10.0.0.1"):
    return {
        "id": device_id, "name": name, "status": {"value": "active"},
        "role": {"name": "Router", "slug": "router"},
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ISR"},
        "site": {"name": "London", "slug": "london"},
        "tenant": {"name": "Test Corp", "slug": "test-corp"},
        "platform": {"name": "IOS-XE", "slug": "ios-xe"},
        "primary_ip4": {"address": f"{ip}/32"},
        "custom_fields": {"os_build": "17.3.1"},
        "tags": [],
        "comments": "",
    }


# ---------------------------------------------------------------------------
# GET /hosts
# ---------------------------------------------------------------------------

@respx.mock
def test_get_hosts_returns_devices_and_vms(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([_nb_device(1, "host-a", "10.0.0.1")])))
    respx.get(f"{NB}/api/virtualization/virtual-machines/").mock(
        return_value=Response(200, json=_page([])))

    resp = client.get("/api/v1/inventory/hosts")

    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["hosts"][0]["name"] == "host-a"


@respx.mock
def test_get_hosts_merges_devices_and_vms(fake_redis):
    vm = {
        "id": 2, "name": "vm-b", "status": {"value": "active"},
        "role": {"name": "Server"}, "cluster": {"name": "Cluster-1"},
        "site": None, "tenant": None, "platform": None,
        "primary_ip4": {"address": "10.0.0.2/32"},
        "custom_fields": {}, "tags": [],
    }
    respx.get(f"{NB}/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([_nb_device(1, "host-a")])))
    respx.get(f"{NB}/api/virtualization/virtual-machines/").mock(
        return_value=Response(200, json=_page([vm])))

    resp = client.get("/api/v1/inventory/hosts")

    assert resp.status_code == 200
    assert resp.json()["count"] == 2


# ---------------------------------------------------------------------------
# GET /managed
# ---------------------------------------------------------------------------

async def test_get_managed_returns_snapshot(fake_redis):
    hosts = [{"host_id": "device:1", "name": "h1", "ip": "10.0.0.1"}]
    await store.save_snapshot(hosts, {"10.0.0.1": "device:1"}, {"h1": "device:1"}, [])

    resp = client.get("/api/v1/inventory/managed")

    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["hosts"][0]["name"] == "h1"
    assert "version" in data


async def test_get_managed_since_version_returns_unchanged(fake_redis):
    hosts = [{"host_id": "device:1", "name": "h1"}]
    version = await store.save_snapshot(hosts, {}, {}, [])

    resp = client.get(f"/api/v1/inventory/managed?since_version={version}")

    assert resp.status_code == 200
    assert resp.json().get("unchanged") is True


async def test_get_managed_stale_version_returns_full_payload(fake_redis):
    hosts = [{"host_id": "device:1", "name": "h1"}]
    version = await store.save_snapshot(hosts, {}, {}, [])

    resp = client.get(f"/api/v1/inventory/managed?since_version={version - 1}")

    assert resp.status_code == 200
    data = resp.json()
    assert "hosts" in data
    assert data.get("unchanged") is not True


# ---------------------------------------------------------------------------
# GET /discovered
# ---------------------------------------------------------------------------

async def test_get_discovered_returns_sightings_and_registered(fake_redis):
    # Sighting (tracking)
    await store.record_sightings([{
        "id": "10.1.0.1", "name": "probe-host", "sources": ["syslog"], "last_seen": 1000.0
    }])
    # Registered (promoted)
    await store.mark_registered("10.1.0.2", 42, "promoted-host")

    resp = client.get("/api/v1/inventory/discovered")

    assert resp.status_code == 200
    data = resp.json()
    ips = {e["ip"] for e in data["discovered"]}
    assert "10.1.0.1" in ips
    assert "10.1.0.2" in ips
    registered = next(e for e in data["discovered"] if e["ip"] == "10.1.0.2")
    assert registered["status"] == "registered"
    assert registered["netbox_id"] == 42


async def test_get_discovered_empty_when_no_sightings(fake_redis):
    resp = client.get("/api/v1/inventory/discovered")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


# ---------------------------------------------------------------------------
# GET /imported
# ---------------------------------------------------------------------------

async def test_get_imported_lists_store_entries(fake_redis):
    await store.mark_imported("10.2.0.1", 100, "host-a",
                               {"ip": "10.2.0.1", "site": "London", "role": "Router"})
    await store.mark_imported("10.2.0.2", 101, "host-b",
                               {"ip": "10.2.0.2", "manufacturer": "Cisco"})

    resp = client.get("/api/v1/inventory/imported")

    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    names = {h["name"] for h in data["imported"]}
    assert names == {"host-a", "host-b"}


async def test_get_imported_cve_monitoring_flag_default_on(fake_redis):
    await store.mark_imported("10.2.0.3", 102, "host-c", {"ip": "10.2.0.3"})

    resp = client.get("/api/v1/inventory/imported")

    host = resp.json()["imported"][0]
    assert host["cve_monitoring"] is True


async def test_get_imported_cve_monitoring_flag_off(fake_redis):
    await store.mark_imported("10.2.0.4", 103, "host-d", {"ip": "10.2.0.4"})
    await store.set_cve_monitoring(["imported:103"], enabled=False)

    resp = client.get("/api/v1/inventory/imported")

    host = resp.json()["imported"][0]
    assert host["cve_monitoring"] is False


async def test_get_imported_empty_when_none(fake_redis):
    resp = client.get("/api/v1/inventory/imported")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------

async def test_get_status_reflects_sync_meta(fake_redis):
    await store.save_snapshot([], {}, {}, [])

    resp = client.get("/api/v1/inventory/status")

    assert resp.status_code == 200
    data = resp.json()
    assert "sync" in data
    assert data["sync"]["version"] >= 1
    assert "mirror" in data
    assert "promoter" in data


async def test_get_status_stale_flag_on_error(fake_redis):
    await store.record_sync_failure("NetBox unreachable")

    resp = client.get("/api/v1/inventory/status")

    assert resp.status_code == 200
    assert resp.json()["sync"]["stale"] is True
