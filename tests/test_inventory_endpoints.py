"""API-layer tests for the new inventory endpoints:
  PATCH /discovered/{device_id}
  POST  /sites
  PATCH /sites/{slug}
"""
import httpx
import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app

client = TestClient(app)

NB = "http://netbox.test"


def _page(results):
    return {"results": results, "next": None}


# ---------------------------------------------------------------------------
# PATCH /api/v1/inventory/discovered/{device_id}
# ---------------------------------------------------------------------------

@respx.mock
def test_patch_discovered_success(fake_redis):
    device = {
        "id": 114065, "name": "10.0.1.1",
        "tags": [{"slug": "halo-discovered"}],
        "device_type": {"manufacturer": {"name": "Unknown"}, "model": "Unknown"},
    }
    respx.get(f"{NB}/api/dcim/devices/114065/").mock(return_value=Response(200, json=device))
    respx.patch(f"{NB}/api/dcim/devices/114065/").mock(
        return_value=Response(200, json={**device, "name": "updated-host"}))

    resp = client.patch("/api/v1/inventory/discovered/114065", json={"name": "updated-host"})
    assert resp.status_code == 200
    assert resp.json()["device_id"] == 114065


@respx.mock
def test_patch_discovered_wrong_tag_returns_404(fake_redis):
    device = {"id": 200, "name": "managed", "tags": [{"slug": "halo-managed"}]}
    respx.get(f"{NB}/api/dcim/devices/200/").mock(return_value=Response(200, json=device))

    resp = client.patch("/api/v1/inventory/discovered/200", json={"name": "x"})
    assert resp.status_code == 404


@respx.mock
def test_patch_discovered_netbox_404_returns_404(fake_redis):
    respx.get(f"{NB}/api/dcim/devices/999/").mock(return_value=Response(404))

    resp = client.patch("/api/v1/inventory/discovered/999", json={"name": "x"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/inventory/sites
# ---------------------------------------------------------------------------

@respx.mock
def test_post_sites_creates_new(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(201, json={"id": 50, "name": "Amsterdam", "slug": "amsterdam"}))

    resp = client.post("/api/v1/inventory/sites", json={"name": "Amsterdam"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["slug"] == "amsterdam"
    assert data["existed"] is False


@respx.mock
def test_post_sites_deduplicates_by_slug(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 51, "name": "Frankfurt", "slug": "frankfurt"}])))

    resp = client.post("/api/v1/inventory/sites", json={"name": "Frankfurt"})
    assert resp.status_code == 201
    assert resp.json()["existed"] is True


def test_post_sites_missing_name_returns_422(fake_redis):
    resp = client.post("/api/v1/inventory/sites", json={"status": "active"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /api/v1/inventory/sites/{slug}
# ---------------------------------------------------------------------------

@respx.mock
def test_patch_sites_updates_status(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 60, "name": "Dublin", "slug": "dublin"}])))
    respx.patch(f"{NB}/api/dcim/sites/60/").mock(
        return_value=Response(200, json={"id": 60, "name": "Dublin", "slug": "dublin"}))

    resp = client.patch("/api/v1/inventory/sites/dublin", json={"status": "planned"})
    assert resp.status_code == 200
    assert resp.json()["id"] == 60


@respx.mock
def test_patch_sites_not_found_returns_404(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))

    resp = client.patch("/api/v1/inventory/sites/no-such-site", json={"status": "active"})
    assert resp.status_code == 404
