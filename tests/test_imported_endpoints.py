"""API-layer tests for PATCH /imported/{device_id} and DELETE /imported/{device_id}.

Follows the same pattern as test_inventory_endpoints.py:
  - sync def tests use TestClient (no store state needed)
  - async def tests use httpx.AsyncClient for tests that need pre-seeded store state
"""
import json

import httpx
import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app
from app.services import netbox_write, store

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _imported_device(device_id=10, name="router-01"):
    return {
        "id": device_id, "name": name,
        "tags": [{"slug": "customer-imported"}],
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "ISR4451"},
    }


# ---------------------------------------------------------------------------
# PATCH /imported/{device_id} — field updates
# ---------------------------------------------------------------------------

@respx.mock
def test_patch_imported_role(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(201, json={"id": 7}))
    patch_call = respx.patch(f"{NB}/api/dcim/devices/10/").mock(
        return_value=Response(200, json=_imported_device()))

    resp = client.patch("/api/v1/inventory/imported/10", json={"role": "Firewall"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["role"] == 7


@respx.mock
def test_patch_imported_manufacturer_and_model(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(201, json={"id": 20}))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-types/").mock(return_value=Response(201, json={"id": 21}))
    patch_call = respx.patch(f"{NB}/api/dcim/devices/10/").mock(
        return_value=Response(200, json=_imported_device()))

    resp = client.patch("/api/v1/inventory/imported/10",
                        json={"manufacturer": "Juniper", "model": "SRX300"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["device_type"] == 21


@respx.mock
def test_patch_imported_platform_via_api(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    respx.get(f"{NB}/api/dcim/platforms/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/platforms/").mock(return_value=Response(201, json={"id": 55}))
    patch_call = respx.patch(f"{NB}/api/dcim/devices/10/").mock(
        return_value=Response(200, json=_imported_device()))

    resp = client.patch("/api/v1/inventory/imported/10", json={"platform": "IOS-XE"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["platform"] == 55


@respx.mock
def test_patch_imported_os_version_via_api(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    patch_call = respx.patch(f"{NB}/api/dcim/devices/10/").mock(
        return_value=Response(200, json=_imported_device()))

    resp = client.patch("/api/v1/inventory/imported/10", json={"os_version": "17.3.1"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["custom_fields"]["os_build"] == "17.3.1"


@respx.mock
def test_patch_imported_non_imported_tag_returns_404(fake_redis):
    device = {"id": 10, "name": "managed", "tags": [{"slug": "halo-managed"}]}
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=device))

    resp = client.patch("/api/v1/inventory/imported/10", json={"name": "x"})
    assert resp.status_code == 404


@respx.mock
def test_patch_imported_netbox_not_found_returns_404(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/999/").mock(return_value=Response(404))

    resp = client.patch("/api/v1/inventory/imported/999", json={"name": "x"})
    assert resp.status_code == 404


@respx.mock
async def test_patch_imported_updates_redis_store(fake_redis):
    """After a successful PATCH the local store should reflect the new values."""
    await store.mark_imported("10.0.1.1", 10, "router-01", {"ip": "10.0.1.1", "site": "paris"})

    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(201, json={"id": 80}))
    respx.patch(f"{NB}/api/dcim/devices/10/").mock(
        return_value=Response(200, json=_imported_device()))

    async with httpx.AsyncClient() as c:
        await netbox_write.update_imported_host(c, 10, {"site": "London"})

    stored = await store.get_imported_by_device_id(10)
    assert stored["site"] == "London"


# ---------------------------------------------------------------------------
# DELETE /imported/{device_id}
# ---------------------------------------------------------------------------

@respx.mock
async def test_delete_imported_success(fake_redis):
    await store.mark_imported("10.0.2.1", 10, "router-01", {"ip": "10.0.2.1"})

    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=_imported_device()))
    delete_call = respx.delete(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(204))

    resp = client.delete("/api/v1/inventory/imported/10")

    assert resp.status_code == 204
    assert delete_call.called
    # Store entry removed
    assert await store.get_imported_by_device_id(10) is None


@respx.mock
def test_delete_imported_wrong_tag_returns_404(fake_redis):
    device = {"id": 10, "name": "managed", "tags": [{"slug": "halo-managed"}]}
    respx.get(f"{NB}/api/dcim/devices/10/").mock(return_value=Response(200, json=device))

    resp = client.delete("/api/v1/inventory/imported/10")
    assert resp.status_code == 404


@respx.mock
async def test_delete_imported_netbox_already_gone_still_clears_store(fake_redis):
    """If NetBox has already deleted the device (404), the store entry should
    still be cleaned up so the host doesn't keep appearing in the UI."""
    await store.mark_imported("10.0.2.2", 11, "ghost-host", {"ip": "10.0.2.2"})

    respx.get(f"{NB}/api/dcim/devices/11/").mock(return_value=Response(200, json={
        **_imported_device(device_id=11, name="ghost-host")}))
    # NetBox device gone by the time we try to delete
    respx.delete(f"{NB}/api/dcim/devices/11/").mock(return_value=Response(404))

    resp = client.delete("/api/v1/inventory/imported/11")

    assert resp.status_code == 204
    assert await store.get_imported_by_device_id(11) is None
