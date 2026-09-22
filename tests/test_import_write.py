"""Unit tests for the CSV-import write path and update_imported_host edge cases.

Covers import_customer_host, overwrite_imported_host, and the cases in
update_imported_host that aren't covered by test_netbox_write.py (which
focuses on platform/os_version).
"""
import json

import httpx
import pytest
import respx
from httpx import Response

from app.services import netbox_write, store

NB = "http://netbox.test"


def _page(results):
    return {"results": results, "next": None}


def _mock_ensures(*, site_id=5, tenant_id=6, role_id=1, mfr_id=2, type_id=3):
    """Wire the _ensure chain for a typical import row. Registers routes on the
    active respx mock context — call inside @respx.mock tests only."""
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(201, json={"id": role_id}))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(201, json={"id": mfr_id}))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-types/").mock(return_value=Response(201, json={"id": type_id}))
    respx.get(f"{NB}/api/extras/tags/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/extras/tags/").mock(return_value=Response(201, json={"id": 99}))
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(201, json={"id": site_id}))
    respx.get(f"{NB}/api/tenancy/tenants/").mock(
        return_value=Response(200, json=_page([{"id": tenant_id, "slug": "test-corp"}])))


def _mock_device_creation(device_id=10, name="router-01", ip="10.1.0.1"):
    """Wire device + interface + IP creation and the primary-IP PATCH."""
    create = respx.post(f"{NB}/api/dcim/devices/").mock(
        return_value=Response(201, json={"id": device_id, "name": name}))
    respx.post(f"{NB}/api/dcim/interfaces/").mock(return_value=Response(201, json={"id": 11}))
    respx.post(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(201, json={"id": 12}))
    respx.patch(f"{NB}/api/dcim/devices/{device_id}/").mock(
        return_value=Response(200, json={"id": device_id, "name": name}))
    return create


# ---------------------------------------------------------------------------
# import_customer_host — happy paths
# ---------------------------------------------------------------------------

@respx.mock
async def test_import_creates_device_with_all_fields(fake_redis):
    row = {"name": "router-01", "ip": "10.1.0.1",
           "role": "Router", "manufacturer": "Cisco", "model": "ASR1001", "site": "London"}
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(200, json=_page([])))
    _mock_ensures()
    device_call = _mock_device_creation()

    async with httpx.AsyncClient() as client:
        result = await netbox_write.import_customer_host(client, row, prefixes=[])

    assert result["status"] == "created"
    assert result["device_id"] == 10
    assert result["name"] == "router-01"

    # Verify store was populated
    stored = await store.get_imported_by_device_id(10)
    assert stored is not None
    assert stored["ip"] == "10.1.0.1"

    # Verify tenant FK is an int (not a dict or string)
    body = json.loads(device_call.calls[0].request.content)
    assert isinstance(body["tenant"], int)
    assert body["site"] == 5
    assert body["role"] == 1


@respx.mock
async def test_import_explicit_site_wins_over_prefix_match(fake_redis):
    """When the CSV row names a site, that beats the IP-prefix lookup."""
    row = {"name": "fw-01", "ip": "192.168.1.1", "site": "London"}
    prefixes = [{"prefix": "192.168.1.0/24", "site": "paris", "site_name": "Paris"}]

    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(200, json=_page([])))
    _mock_ensures(site_id=7)
    _mock_device_creation(device_id=20, name="fw-01", ip="192.168.1.1")

    async with httpx.AsyncClient() as client:
        result = await netbox_write.import_customer_host(client, row, prefixes=prefixes)

    assert result["status"] == "created"
    # site slug used should be "london" (from explicit name), not the cached paris slug
    assert await store.get_nbid("site:london") == 7
    assert await store.get_nbid("site:paris") is None


@respx.mock
async def test_import_skips_already_assigned_ip(fake_redis):
    row = {"name": "host-x", "ip": "10.2.0.1"}
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([{"id": 5, "assigned_object_id": 99}])))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.import_customer_host(client, row, prefixes=[])

    assert result["status"] == "skipped"
    assert "already assigned" in result["reason"]
    # Nothing should have been created in the store
    assert await store.get_imported_by_device_id(99) is None


@respx.mock
async def test_import_name_collision_retries_with_ip_suffix(fake_redis):
    row = {"name": "router-01", "ip": "10.3.0.1"}
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(200, json=_page([])))
    _mock_ensures()
    # First attempt: NetBox rejects the name
    device_calls = respx.post(f"{NB}/api/dcim/devices/").mock(side_effect=[
        Response(400, json={"name": ["Device with this name already exists."]}),
        Response(201, json={"id": 30, "name": "router-01-10.3.0.1"}),
    ])
    respx.post(f"{NB}/api/dcim/interfaces/").mock(return_value=Response(201, json={"id": 31}))
    respx.post(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(201, json={"id": 32}))
    respx.patch(f"{NB}/api/dcim/devices/30/").mock(
        return_value=Response(200, json={"id": 30, "name": "router-01-10.3.0.1"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.import_customer_host(client, row, prefixes=[])

    assert result["status"] == "created"
    assert result["name"] == "router-01-10.3.0.1"
    assert device_calls.call_count == 2
    second_body = json.loads(device_calls.calls[1].request.content)
    assert second_body["name"] == "router-01-10.3.0.1"


# ---------------------------------------------------------------------------
# import endpoint — summary counts via API
# ---------------------------------------------------------------------------

@respx.mock
def test_import_api_returns_summary_counts(fake_redis):
    from fastapi.testclient import TestClient
    from app.main import app

    # Row 1: fresh IP → will be created
    # Row 2: IP already assigned in NetBox → skipped
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(side_effect=[
        Response(200, json=_page([])),                                # row 1: not found
        Response(200, json=_page([{"id": 9, "assigned_object_id": 77}])),  # row 2: assigned
    ])
    _mock_ensures()
    _mock_device_creation()

    resp = TestClient(app).post("/api/v1/inventory/import", json={
        "rows": [
            {"name": "host-a", "ip": "10.10.0.1", "role": "Router", "manufacturer": "Cisco", "model": "ISR"},
            {"name": "host-b", "ip": "10.10.0.2"},
        ]
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["created"] == 1
    assert data["skipped"] == 1
    assert data["failed"] == 0


# ---------------------------------------------------------------------------
# overwrite_imported_host
# ---------------------------------------------------------------------------

@respx.mock
async def test_overwrite_imported_delegates_to_update(fake_redis):
    device = {
        "id": 50, "name": "old-name",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ISR"},
    }
    await store.mark_imported("10.5.0.1", 50, "old-name", {"ip": "10.5.0.1"})
    respx.get(f"{NB}/api/dcim/devices/50/").mock(return_value=Response(200, json=device))
    respx.patch(f"{NB}/api/dcim/devices/50/").mock(
        return_value=Response(200, json={**device, "name": "new-name"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.overwrite_imported_host(client, 50,
                                                            {"name": "new-name", "ip": "10.5.0.1"})

    assert result["status"] == "updated"
    assert result["device_id"] == 50
    assert result["name"] == "new-name"


# ---------------------------------------------------------------------------
# update_imported_host — edge cases
# ---------------------------------------------------------------------------

@respx.mock
async def test_update_imported_partial_manufacturer_inherits_current_model(fake_redis):
    """If only manufacturer is updated (no model), the existing model is kept."""
    device = {
        "id": 60, "name": "sw-01",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ASR1001"},
    }
    await store.mark_imported("10.6.0.1", 60, "sw-01", {"ip": "10.6.0.1", "manufacturer": "Cisco", "model": "ASR1001"})
    respx.get(f"{NB}/api/dcim/devices/60/").mock(return_value=Response(200, json=device))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(201, json={"id": 70}))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))
    type_call = respx.post(f"{NB}/api/dcim/device-types/").mock(
        return_value=Response(201, json={"id": 71}))
    respx.patch(f"{NB}/api/dcim/devices/60/").mock(
        return_value=Response(200, json=device))

    async with httpx.AsyncClient() as client:
        await netbox_write.update_imported_host(client, 60, {"manufacturer": "Aruba"})

    type_body = json.loads(type_call.calls[0].request.content)
    # model should be inherited from the current device_type, not overridden
    assert type_body["model"] == "ASR1001"
    assert type_body["manufacturer"] == 70   # new manufacturer id


@respx.mock
async def test_update_imported_no_patch_when_nothing_changes(fake_redis):
    """Empty updates dict must not issue any PATCH to NetBox."""
    device = {
        "id": 61, "name": "ap-01",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "HPE"}, "model": "AP515"},
    }
    await store.mark_imported("10.6.0.2", 61, "ap-01", {"ip": "10.6.0.2"})
    respx.get(f"{NB}/api/dcim/devices/61/").mock(return_value=Response(200, json=device))
    patch_route = respx.patch(f"{NB}/api/dcim/devices/61/").mock(
        return_value=Response(200, json=device))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.update_imported_host(client, 61, {})

    assert result["device_id"] == 61
    assert patch_route.call_count == 0


@respx.mock
async def test_update_imported_name_and_site(fake_redis):
    device = {
        "id": 62, "name": "rtr-old",
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ISR4451"},
    }
    await store.mark_imported("10.6.0.3", 62, "rtr-old", {"ip": "10.6.0.3", "site": "paris"})
    respx.get(f"{NB}/api/dcim/devices/62/").mock(return_value=Response(200, json=device))
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(201, json={"id": 80}))
    patch_call = respx.patch(f"{NB}/api/dcim/devices/62/").mock(
        return_value=Response(200, json={**device, "name": "rtr-new"}))

    async with httpx.AsyncClient() as client:
        result = await netbox_write.update_imported_host(client, 62,
                                                         {"name": "rtr-new", "site": "Berlin"})

    assert result["name"] == "rtr-new"
    body = json.loads(patch_call.calls[0].request.content)
    assert body["name"] == "rtr-new"
    assert body["site"] == 80

    # Store should reflect updated values
    stored = await store.get_imported_by_device_id(62)
    assert stored["site"] == "Berlin"


@respx.mock
async def test_update_imported_non_imported_tag_rejected(fake_redis):
    device = {"id": 63, "name": "managed", "tags": [{"slug": "halo-managed"}]}
    respx.get(f"{NB}/api/dcim/devices/63/").mock(return_value=Response(200, json=device))

    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="not a customer-imported host"):
            await netbox_write.update_imported_host(client, 63, {"name": "x"})
