"""Tests for GET /api/v1/inventory/options."""
import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _role(name, slug=None):
    return {"id": 1, "name": name, "slug": slug or name.lower()}


def _manufacturer(name, slug=None):
    return {"id": 1, "name": name, "slug": slug or name.lower()}


def _platform(name, slug=None):
    return {"id": 1, "name": name, "slug": slug or name.lower()}


def _device_type(model, mfr_slug="cisco"):
    return {"id": 1, "model": model, "slug": model.lower().replace(" ", "-"),
            "manufacturer": {"id": 1, "name": "Cisco", "slug": mfr_slug}}


@respx.mock
def test_options_returns_all_fields(fake_redis):
    respx.get(f"{NB}/api/dcim/device-roles/").mock(
        return_value=Response(200, json=_page([_role("Router"), _role("Switch")])))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(
        return_value=Response(200, json=_page([_manufacturer("Cisco"), _manufacturer("Juniper")])))
    respx.get(f"{NB}/api/dcim/platforms/").mock(
        return_value=Response(200, json=_page([_platform("IOS-XE"), _platform("JunOS")])))
    respx.get(f"{NB}/api/dcim/device-types/").mock(
        return_value=Response(200, json=_page([_device_type("ASR 1001"), _device_type("ISR 4321")])))

    resp = client.get("/api/v1/inventory/options")

    assert resp.status_code == 200
    body = resp.json()
    assert body["roles"] == ["Router", "Switch"]
    assert body["manufacturers"] == ["Cisco", "Juniper"]
    assert body["platforms"] == ["IOS-XE", "JunOS"]
    assert len(body["device_types"]) == 2
    assert body["device_types"][0]["name"] == "ASR 1001"
    assert body["device_types"][0]["manufacturer"] == "cisco"


@respx.mock
def test_options_sorted_alphabetically(fake_redis):
    respx.get(f"{NB}/api/dcim/device-roles/").mock(
        return_value=Response(200, json=_page([_role("Switch"), _role("Router"), _role("Firewall")])))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(
        return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/platforms/").mock(
        return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/device-types/").mock(
        return_value=Response(200, json=_page([])))

    resp = client.get("/api/v1/inventory/options")

    assert resp.status_code == 200
    assert resp.json()["roles"] == ["Firewall", "Router", "Switch"]


@respx.mock
def test_options_all_empty(fake_redis):
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/platforms/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))

    resp = client.get("/api/v1/inventory/options")

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"roles": [], "manufacturers": [], "platforms": [], "device_types": []}


@respx.mock
def test_options_netbox_error_returns_502(fake_redis):
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(500, json={}))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/platforms/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/device-types/").mock(return_value=Response(200, json=_page([])))

    resp = client.get("/api/v1/inventory/options")

    assert resp.status_code == 502


@respx.mock
def test_options_device_type_without_manufacturer(fake_redis):
    """Device types with a null manufacturer field don't crash."""
    respx.get(f"{NB}/api/dcim/device-roles/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/manufacturers/").mock(return_value=Response(200, json=_page([])))
    respx.get(f"{NB}/api/dcim/platforms/").mock(return_value=Response(200, json=_page([])))
    dt_no_mfr = {"id": 2, "model": "Generic Switch", "slug": "generic-switch", "manufacturer": None}
    respx.get(f"{NB}/api/dcim/device-types/").mock(
        return_value=Response(200, json=_page([dt_no_mfr])))

    resp = client.get("/api/v1/inventory/options")

    assert resp.status_code == 200
    assert resp.json()["device_types"][0]["manufacturer"] == ""
