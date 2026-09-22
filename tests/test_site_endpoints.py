"""Tests for GET/POST /api/v1/inventory/sites and PATCH /api/v1/inventory/sites/{slug}."""
import json

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _mock_site_tag():
    """Mock the _ensure call for the halo-site tag."""
    respx.get(f"{NB}/api/extras/tags/").mock(return_value=Response(200, json=_page([{"id": 99, "slug": "halo-site"}])))


def _nb_site(site_id=1, name="London", slug="london", status="active"):
    return {"id": site_id, "name": name, "slug": slug,
            "status": {"value": status, "label": status.capitalize()},
            "description": ""}


# ---------------------------------------------------------------------------
# GET /sites
# ---------------------------------------------------------------------------

@respx.mock
def test_list_sites_returns_all(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([
            _nb_site(1, "London", "london"),
            _nb_site(2, "Paris", "paris"),
        ])))

    resp = client.get("/api/v1/inventory/sites")

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert len(body["sites"]) == 2
    assert body["sites"][0]["slug"] == "london"
    assert body["sites"][1]["slug"] == "paris"


@respx.mock
def test_list_sites_empty(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([])))

    resp = client.get("/api/v1/inventory/sites")

    assert resp.status_code == 200
    assert resp.json() == {"sites": [], "count": 0}


@respx.mock
def test_list_sites_netbox_error_returns_502(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(500, json={}))

    resp = client.get("/api/v1/inventory/sites")

    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POST /sites
# ---------------------------------------------------------------------------

@respx.mock
def test_create_site_new(fake_redis):
    _mock_site_tag()
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    post_call = respx.post(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(201, json=_nb_site(10, "Amsterdam", "amsterdam")))

    resp = client.post("/api/v1/inventory/sites", json={"name": "Amsterdam"})

    assert resp.status_code == 201
    body = resp.json()
    assert body["slug"] == "amsterdam"
    assert body["existed"] is False
    payload = json.loads(post_call.calls[0].request.content)
    assert payload["slug"] == "amsterdam"
    assert payload["tags"] == [{"id": 99}]


@respx.mock
def test_create_site_already_exists_returns_existing(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([_nb_site(5, "London", "london")])))

    resp = client.post("/api/v1/inventory/sites", json={"name": "London"})

    assert resp.status_code == 201
    body = resp.json()
    assert body["id"] == 5
    assert body["existed"] is True


@respx.mock
def test_create_site_race_condition_retry(fake_redis):
    """POST 400 on slug conflict triggers a GET retry and returns the existing site."""
    _mock_site_tag()
    respx.get(f"{NB}/api/dcim/sites/").mock(side_effect=[
        Response(200, json=_page([])),
        Response(200, json=_page([_nb_site(7, "Berlin", "berlin")])),
    ])
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(400, json={"slug": ["already taken"]}))

    resp = client.post("/api/v1/inventory/sites", json={"name": "Berlin"})

    assert resp.status_code == 201
    assert resp.json()["id"] == 7
    assert resp.json()["existed"] is True


@respx.mock
def test_create_site_with_description(fake_redis):
    _mock_site_tag()
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    post_call = respx.post(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(201, json=_nb_site(11, "Tokyo", "tokyo")))

    resp = client.post("/api/v1/inventory/sites",
                       json={"name": "Tokyo", "description": "Japan DC"})

    assert resp.status_code == 201
    payload = json.loads(post_call.calls[0].request.content)
    assert payload["description"] == "Japan DC"


def test_create_site_missing_name_returns_422(fake_redis):
    resp = client.post("/api/v1/inventory/sites", json={"status": "active"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /sites/{slug}
# ---------------------------------------------------------------------------

@respx.mock
def test_update_site_status(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([_nb_site(5, "London", "london")])))
    patch_call = respx.patch(f"{NB}/api/dcim/sites/5/").mock(
        return_value=Response(200, json=_nb_site(5, "London", "london", "planned")))

    resp = client.patch("/api/v1/inventory/sites/london", json={"status": "planned"})

    assert resp.status_code == 200
    assert resp.json()["slug"] == "london"
    body = json.loads(patch_call.calls[0].request.content)
    assert body["status"] == "planned"


@respx.mock
def test_update_site_description(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([_nb_site(5, "London", "london")])))
    patch_call = respx.patch(f"{NB}/api/dcim/sites/5/").mock(
        return_value=Response(200, json=_nb_site(5, "London", "london")))

    resp = client.patch("/api/v1/inventory/sites/london",
                        json={"description": "HQ datacenter"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["description"] == "HQ datacenter"


@respx.mock
def test_update_site_not_found_returns_404(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))

    resp = client.patch("/api/v1/inventory/sites/nonexistent", json={"status": "active"})

    assert resp.status_code == 404


@respx.mock
def test_update_site_no_op_skips_patch(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([_nb_site(5, "London", "london")])))
    patch_route = respx.patch(f"{NB}/api/dcim/sites/5/").mock(
        return_value=Response(200, json=_nb_site(5, "London", "london")))

    resp = client.patch("/api/v1/inventory/sites/london", json={})

    assert resp.status_code == 200
    assert patch_route.call_count == 0
