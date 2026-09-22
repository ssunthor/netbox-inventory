"""Tests for POST /api/v1/inventory/hosts (single-host creation)."""
import json

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app
from app.services import store

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _mock_full_create(device_id=10, name="router-01", ip="10.1.0.1"):
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(201, json={"id": 1}))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(201, json={"id": 2}))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/device-types/").mock(return_value=Response(201, json={"id": 3}))
    respx.get(f"{NB}/api/extras/tags/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/extras/tags/").mock(return_value=Response(201, json={"id": 99}))
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(201, json={"id": 5}))
    respx.get(f"{NB}/api/tenancy/tenants/").mock(
        return_value=Response(200, json=_page([{"id": 6, "slug": "test-corp"}])))
    device_call = respx.post(f"{NB}/api/dcim/devices/").mock(
        return_value=Response(201, json={"id": device_id, "name": name}))
    respx.post(f"{NB}/api/dcim/interfaces/").mock(return_value=Response(201, json={"id": 11}))
    respx.post(f"{NB}/api/ipam/ip-addresses/").mock(return_value=Response(201, json={"id": 12}))
    respx.patch(f"{NB}/api/dcim/devices/{device_id}/").mock(
        return_value=Response(200, json={"id": device_id, "name": name}))
    return device_call


@respx.mock
def test_create_host_returns_created(fake_redis):
    _mock_full_create()
    resp = client.post("/api/v1/inventory/hosts",
                       json={"name": "router-01", "ip": "10.1.0.1", "site": "London"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "created"
    assert data["device_id"] == 10
    assert data["name"] == "router-01"


@respx.mock
def test_create_host_minimum_fields(fake_redis):
    """name + ip is sufficient; optional fields default to Unknown."""
    _mock_full_create(device_id=20, name="host-x", ip="10.2.0.1")
    resp = client.post("/api/v1/inventory/hosts", json={"name": "host-x", "ip": "10.2.0.1"})
    assert resp.status_code == 201
    assert resp.json()["status"] == "created"


@respx.mock
def test_create_host_ip_already_assigned_returns_409(fake_redis):
    respx.get(f"{NB}/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([{"id": 9, "assigned_object_id": 77}])))
    resp = client.post("/api/v1/inventory/hosts", json={"name": "dup", "ip": "10.3.0.1"})
    assert resp.status_code == 409


@respx.mock
async def test_create_host_persists_to_store(fake_redis):
    _mock_full_create(device_id=30, name="sw-01", ip="10.4.0.1")
    client.post("/api/v1/inventory/hosts", json={"name": "sw-01", "ip": "10.4.0.1"})
    stored = await store.get_imported_by_device_id(30)
    assert stored is not None
    assert stored["ip"] == "10.4.0.1"
