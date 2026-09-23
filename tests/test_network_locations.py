import pytest
import respx
from fastapi import HTTPException
from httpx import Response

from app.api.v1 import inventory
from app.schemas import NetworkLocationAssignment
from app.services import classify, netbox, store


async def _seed_synced_prefixes():
    await store.save_snapshot(
        hosts=[], ip_index={}, name_index={},
        prefixes=[{"prefix": "10.250.47.0/27", "site": "lon8", "site_name": "LON8"},
                  {"prefix": "10.0.0.0/8", "site": "global", "site_name": "Global"}])


async def test_manual_labels_merge_over_synced_prefixes(fake_redis):
    await _seed_synced_prefixes()
    await store.set_manual_prefixes([
        {"prefix": "10.99.1.0/24", "site": "dal", "site_name": "Dallas"},
        # Same prefix as a synced entry - the manual label must win.
        {"prefix": "10.0.0.0/8", "site": "hq", "site_name": "HQ"},
    ])

    merged = await store.get_prefixes()
    assert [p["prefix"] for p in merged] == ["10.250.47.0/27", "10.99.1.0/24", "10.0.0.0/8"]
    assert merged[2]["site_name"] == "HQ" and merged[2]["manual"] is True

    # classify sees the manual label through the same merged list
    assert classify.site_for_ip("10.99.1.7", merged)["site"] == "dal"

    # ...and the managed payload the backend polls carries the merge too
    payload = await store.get_managed_payload()
    assert {p["prefix"] for p in payload["prefixes"]} == {p["prefix"] for p in merged}
    assert "sites" in payload


async def test_manual_labels_survive_resync(fake_redis):
    await store.set_manual_prefixes(
        [{"prefix": "10.99.1.0/24", "site": "dal", "site_name": "Dallas"}])
    version_before = (await store.get_meta())["version"]
    await _seed_synced_prefixes()  # wholesale rebuild of inv:prefixes
    merged = await store.get_prefixes()
    assert any(p["prefix"] == "10.99.1.0/24" for p in merged)
    assert (await store.get_meta())["version"] > version_before


async def test_network_location_endpoints(fake_redis):
    resp = await inventory.post_network_locations(NetworkLocationAssignment(
        prefixes=["10.99.1.0/24", "10.99.2.5/24"], site_name="Dallas"))
    assert resp["saved"] == 2
    by_prefix = {m["prefix"]: m for m in resp["mappings"]}
    # host-bit prefix normalized, slug derived from the name
    assert by_prefix["10.99.2.0/24"]["site"] == "dallas"

    listing = await inventory.get_network_locations()
    assert len(listing["mappings"]) == 2
    assert any(p["prefix"] == "10.99.1.0/24" for p in listing["prefixes"])

    assert (await inventory.delete_network_location("10.99.1.0/24"))["deleted"]
    with pytest.raises(HTTPException) as exc:
        await inventory.delete_network_location("10.99.1.0/24")
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await inventory.post_network_locations(NetworkLocationAssignment(
            prefixes=["not-a-cidr"], site_name="Dallas"))
    assert exc.value.status_code == 422


@respx.mock
async def test_build_sites_coordinates(fake_redis, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "GEOCODE_URL", "http://geo.test/search")

    respx.get("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(200, json={"results": [
            {"name": "LON8", "latitude": 51.5, "longitude": -0.12},
            # Not referenced by any host: listed (and geocoded) anyway
            {"name": "PRG1", "slug": "prg1", "physical_address": "Na Prikope 1\nPrague"},
        ], "next": None}))
    respx.get("http://gtt.test/api/dcim/sites/").mock(
        return_value=Response(200, json={"results": [
            # GT-T sites are enrich-only: an unreferenced one is never listed
            {"name": "OTHER-CUSTOMER", "latitude": 1.0, "longitude": 1.0},
        ], "next": None}))
    geo_route = respx.get("http://geo.test/search").mock(
        return_value=Response(200, json=[{"lat": "32.77", "lon": "-96.79"}]))

    hosts = [{"site": "ACME-US-TXDAL-MAIN"}, {"site": "LON8"}]
    prefixes = [{"prefix": "10.0.0.0/8", "site": "cst", "site_name": "CST"}]
    site_addresses = {"ACME-US-TXDAL-MAIN": "100 Main St, Dallas, TX, 75201"}

    sites = {s["site_name"]: s for s in
             await netbox.build_sites(hosts, prefixes, site_addresses)}

    assert sites["LON8"]["latitude"] == 51.5  # DCIM coordinates win, no geocode
    dal = sites["ACME-US-TXDAL-MAIN"]
    assert (dal["latitude"], dal["longitude"]) == (32.77, -96.79)  # geocoded
    queried = {c.request.url.params["q"] for c in geo_route.calls}
    assert queried == {"100 Main St, Dallas, TX, 75201", "Na Prikope 1, Prague"}
    prg = sites["PRG1"]
    assert prg["site"] == "prg1" and prg["latitude"] == 32.77  # customer DCIM site, geocoded
    assert "OTHER-CUSTOMER" not in sites
    # Prefix owners are catalogued too (no coordinates until a DCIM record or address exists)
    assert set(sites) == {"LON8", "ACME-US-TXDAL-MAIN", "PRG1", "CST"}
    assert sites["CST"]["site"] == "cst" and sites["CST"]["latitude"] is None

    # Second build hits the inv:geocode cache, not the geocoder
    await netbox.build_sites(hosts, prefixes, site_addresses)
    assert len(geo_route.calls) == 2
