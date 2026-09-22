"""Tests for discovered_ips in the managed payload.

The backend's reconcile_inventory_stamps() reads discovered_ips from
GET /managed to distinguish auto-promoted discovered devices (which should
show the edit UI with halo_discovered=True) from GTT-managed devices (which
should be managed=True). These tests verify the inventory service produces
the correct contract.
"""
import pytest

from app.services import store


# ---------------------------------------------------------------------------
# store.get_managed_payload — discovered_ips field
# ---------------------------------------------------------------------------

async def test_discovered_ips_present_after_mark_registered(fake_redis):
    await store.save_snapshot([], {}, {}, [])
    await store.mark_registered("10.1.2.3", 42, "disc-host")

    payload = await store.get_managed_payload()

    assert "discovered_ips" in payload
    assert payload["discovered_ips"]["10.1.2.3"] == "device:42"


async def test_discovered_ips_empty_with_no_registered_hosts(fake_redis):
    await store.save_snapshot([], {}, {}, [])

    payload = await store.get_managed_payload()

    assert payload["discovered_ips"] == {}


async def test_discovered_ips_includes_all_registered_hosts(fake_redis):
    await store.save_snapshot([], {}, {}, [])
    await store.mark_registered("10.0.0.1", 10, "host-a")
    await store.mark_registered("10.0.0.2", 20, "host-b")

    payload = await store.get_managed_payload()

    assert payload["discovered_ips"]["10.0.0.1"] == "device:10"
    assert payload["discovered_ips"]["10.0.0.2"] == "device:20"


async def test_discovered_ips_removed_after_delete_registered(fake_redis):
    await store.save_snapshot([], {}, {}, [])
    await store.mark_registered("10.5.5.5", 99, "temp-host")
    assert (await store.get_managed_payload())["discovered_ips"].get("10.5.5.5") == "device:99"

    await store.delete_registered("10.5.5.5")

    assert (await store.get_managed_payload())["discovered_ips"].get("10.5.5.5") is None


async def test_discovered_ips_excludes_gtt_managed_ips(fake_redis):
    """IPs added to ip_index by the GTT sync must not appear in discovered_ips;
    only entries written by mark_registered (inv:registered) are included."""
    gtt_hosts = [{"host_id": "device:1", "name": "gtt-router"}]
    await store.save_snapshot(gtt_hosts, {"172.16.0.1": "device:1"}, {}, [])

    payload = await store.get_managed_payload()

    assert "172.16.0.1" not in payload["discovered_ips"]


async def test_discovered_ips_only_includes_hosts_with_device_id(fake_redis):
    """A registration without a device_id (edge case) must not appear."""
    await store.save_snapshot([], {}, {}, [])
    await store.mark_registered("10.7.7.7", None, "no-id-host")

    payload = await store.get_managed_payload()

    assert "10.7.7.7" not in payload["discovered_ips"]


# ---------------------------------------------------------------------------
# Interaction: gtt-managed + discovered coexist without collision
# ---------------------------------------------------------------------------

async def test_gtt_and_discovered_coexist_in_payload(fake_redis):
    gtt_hosts = [{"host_id": "device:5", "name": "gtt-switch"}]
    await store.save_snapshot(gtt_hosts, {"192.168.1.1": "device:5"}, {}, [])
    await store.mark_registered("10.20.30.40", 55, "promoted-host")

    payload = await store.get_managed_payload()

    # GTT host in ip_index but NOT in discovered_ips
    assert "192.168.1.1" in payload["ip_index"]
    assert "192.168.1.1" not in payload["discovered_ips"]
    # Discovered host in BOTH ip_index (added by mark_registered) AND discovered_ips
    assert "10.20.30.40" in payload["ip_index"]
    assert payload["discovered_ips"]["10.20.30.40"] == "device:55"
    # GTT host in hosts list; discovered host is NOT
    assert any(h["host_id"] == "device:5" for h in payload["hosts"])
    assert not any(h.get("host_id") == "device:55" for h in payload["hosts"])
