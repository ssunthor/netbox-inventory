"""Tests for POST /api/v1/inventory/prefixes and PATCH /api/v1/inventory/prefixes."""
import json

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.main import app

NB = "http://netbox.test"
client = TestClient(app)


def _page(results):
    return {"results": results, "next": None}


def _nb_prefix(prefix_id=1, prefix="10.0.0.0/24", status="active"):
    return {"id": prefix_id, "prefix": prefix, "status": {"value": status},
            "site": None, "description": ""}


# ---------------------------------------------------------------------------
# POST /prefixes
# ---------------------------------------------------------------------------

@respx.mock
def test_create_prefix_minimal(fake_redis):
    post_call = respx.post(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(201, json=_nb_prefix(1, "10.0.0.0/24")))

    resp = client.post("/api/v1/inventory/prefixes",
                       json={"prefix": "10.0.0.0/24", "status": "active"})

    assert resp.status_code == 201
    body = json.loads(post_call.calls[0].request.content)
    assert body["prefix"] == "10.0.0.0/24"
    assert body["status"] == "active"


@respx.mock
def test_create_prefix_with_site_resolves_fk(fake_redis):
    respx.get(f"{NB}/api/dcim/sites/").mock(return_value=Response(200, json=_page([])))
    respx.post(f"{NB}/api/dcim/sites/").mock(return_value=Response(201, json={"id": 50}))
    post_call = respx.post(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(201, json=_nb_prefix(2, "192.168.1.0/24")))

    resp = client.post("/api/v1/inventory/prefixes",
                       json={"prefix": "192.168.1.0/24", "site_slug": "london"})

    assert resp.status_code == 201
    body = json.loads(post_call.calls[0].request.content)
    assert body["site"] == 50


@respx.mock
def test_create_prefix_with_description(fake_redis):
    post_call = respx.post(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(201, json=_nb_prefix(3, "172.16.0.0/12")))

    resp = client.post("/api/v1/inventory/prefixes",
                       json={"prefix": "172.16.0.0/12", "description": "Internal"})

    assert resp.status_code == 201
    body = json.loads(post_call.calls[0].request.content)
    assert body["description"] == "Internal"


def test_create_prefix_missing_prefix_returns_422(fake_redis):
    resp = client.post("/api/v1/inventory/prefixes", json={"status": "active"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /prefixes
# ---------------------------------------------------------------------------

@respx.mock
def test_update_prefix_status(fake_redis):
    respx.get(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(200, json=_page([_nb_prefix(10, "10.0.0.0/24")])))
    patch_call = respx.patch(f"{NB}/api/ipam/prefixes/10/").mock(
        return_value=Response(200, json=_nb_prefix(10, "10.0.0.0/24", "planned")))

    resp = client.patch("/api/v1/inventory/prefixes",
                        json={"prefix": "10.0.0.0/24", "status": "planned"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["status"] == "planned"


@respx.mock
def test_update_prefix_with_site(fake_redis):
    respx.get(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(200, json=_page([_nb_prefix(11, "10.1.0.0/24")])))
    respx.get(f"{NB}/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 60, "slug": "amsterdam"}])))
    patch_call = respx.patch(f"{NB}/api/ipam/prefixes/11/").mock(
        return_value=Response(200, json=_nb_prefix(11, "10.1.0.0/24")))

    resp = client.patch("/api/v1/inventory/prefixes",
                        json={"prefix": "10.1.0.0/24", "site_slug": "amsterdam"})

    assert resp.status_code == 200
    body = json.loads(patch_call.calls[0].request.content)
    assert body["site"] == 60


@respx.mock
def test_update_prefix_not_found_returns_404(fake_redis):
    respx.get(f"{NB}/api/ipam/prefixes/").mock(return_value=Response(200, json=_page([])))

    resp = client.patch("/api/v1/inventory/prefixes",
                        json={"prefix": "99.0.0.0/8", "status": "active"})

    assert resp.status_code == 404


@respx.mock
def test_update_prefix_no_changes_returns_existing(fake_redis):
    """When no patchable fields are provided, no PATCH call is made."""
    respx.get(f"{NB}/api/ipam/prefixes/").mock(
        return_value=Response(200, json=_page([_nb_prefix(12, "10.2.0.0/24")])))
    patch_route = respx.patch(f"{NB}/api/ipam/prefixes/12/").mock(
        return_value=Response(200, json=_nb_prefix(12, "10.2.0.0/24")))

    resp = client.patch("/api/v1/inventory/prefixes", json={"prefix": "10.2.0.0/24"})

    assert resp.status_code == 200
    assert patch_route.call_count == 0
