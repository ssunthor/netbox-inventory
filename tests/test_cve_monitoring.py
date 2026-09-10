import json

import httpx
import respx
from httpx import Response

from app.services import cve_monitoring, store


def _page(results):
    return {"results": results, "next": None}


CF_URL = "http://netbox.test/api/extras/custom-fields/"


@respx.mock
async def test_ensure_custom_field_creates_and_caches(fake_redis):
    respx.get(f"{CF_URL}?name=cve_monitoring").mock(
        return_value=Response(200, json=_page([])))
    create = respx.post(CF_URL).mock(return_value=Response(201, json={"id": 9}))

    async with httpx.AsyncClient() as client:
        assert await cve_monitoring.ensure_custom_field(client) == 9
        payload = json.loads(create.calls[0].request.content)
        # Cached: no further HTTP on the second call (reset also clears
        # recorded calls, so the payload was captured above).
        respx.reset()
        assert await cve_monitoring.ensure_custom_field(client) == 9

    assert payload["object_types"] == cve_monitoring.OBJECT_TYPES
    assert payload["type"] == "boolean" and payload["default"] is True


@respx.mock
async def test_ensure_custom_field_falls_back_to_content_types(fake_redis):
    respx.get(f"{CF_URL}?name=cve_monitoring").mock(
        return_value=Response(200, json=_page([])))
    create = respx.post(CF_URL).mock(side_effect=[
        Response(400, json={"object_types": ["Unknown field."]}),
        Response(201, json={"id": 11}),
    ])

    async with httpx.AsyncClient() as client:
        assert await cve_monitoring.ensure_custom_field(client) == 11

    retry = json.loads(create.calls[1].request.content)
    assert "content_types" in retry and "object_types" not in retry


async def _prime_field_cache():
    await store.set_nbid("customfield:cve_monitoring", 9)


@respx.mock
async def test_set_hosts_managed_and_imported(fake_redis):
    await _prime_field_cache()
    # Managed host device:12 mirrors to customer device 70.
    await store.set_mirror_entry("device:12", 70, "fp")
    patch_managed = respx.patch("http://netbox.test/api/dcim/devices/70/").mock(
        return_value=Response(200, json={"id": 70}))
    patch_imported = respx.patch("http://netbox.test/api/dcim/devices/57/").mock(
        return_value=Response(200, json={"id": 57}))

    result = await cve_monitoring.set_hosts(
        [{"host_id": "device:12", "source": "managed"},
         {"host_id": "device:57", "source": "imported"}], enabled=False)

    assert result["updated"] == 2 and result["failed"] == 0
    assert json.loads(patch_managed.calls[0].request.content) == {
        "custom_fields": {"cve_monitoring": False}}
    assert patch_imported.called
    off = await store.get_cve_monitoring_off()
    assert off == {"device:12", "imported:57"}
    # Version bumped so the backend's since_version poll sees a change.
    assert (await store.get_meta())["version"] == 1

    # Re-enable clears the off-list.
    respx.patch("http://netbox.test/api/dcim/devices/70/").mock(
        return_value=Response(200, json={"id": 70}))
    respx.patch("http://netbox.test/api/dcim/devices/57/").mock(
        return_value=Response(200, json={"id": 57}))
    await cve_monitoring.set_hosts(
        [{"host_id": "device:12", "source": "managed"},
         {"host_id": "device:57", "source": "imported"}], enabled=True)
    assert await store.get_cve_monitoring_off() == set()


@respx.mock
async def test_set_hosts_unmirrored_target_fails_without_blocking_rest(fake_redis):
    await _prime_field_cache()
    await store.set_mirror_entry("vm:3", 80, "fp")
    respx.patch("http://netbox.test/api/virtualization/virtual-machines/80/").mock(
        return_value=Response(200, json={"id": 80}))

    result = await cve_monitoring.set_hosts(
        [{"host_id": "device:99", "source": "managed"},   # never mirrored
         {"host_id": "vm:3", "source": "managed"}], enabled=False)

    assert result["updated"] == 1 and result["failed"] == 1
    statuses = {r["host_id"]: r["status"] for r in result["results"]}
    assert statuses == {"device:99": "failed", "vm:3": "ok"}
    assert await store.get_cve_monitoring_off() == {"vm:3"}


@respx.mock
async def test_refresh_from_netbox_rebuilds_off_list(fake_redis):
    await store.set_mirror_entry("device:12", 70, "fp")
    await store.set_mirror_entry("vm:3", 80, "fp")
    await store.mark_imported("10.0.0.4", 57, "imp-a", {})
    # Stale cache entry that NetBox no longer agrees with:
    await store.set_cve_monitoring(["device:12"], False)

    respx.get(url__regex=r"http://netbox\.test/api/dcim/devices/.*").mock(
        return_value=Response(200, json=_page([
            {"id": 70, "custom_fields": {"cve_monitoring": True}},
            {"id": 57, "custom_fields": {"cve_monitoring": False}},
        ])))
    respx.get(url__regex=r"http://netbox\.test/api/virtualization/virtual-machines/.*").mock(
        return_value=Response(200, json=_page([
            {"id": 80, "custom_fields": {"cve_monitoring": False}},
        ])))

    async with httpx.AsyncClient() as client:
        count = await cve_monitoring.refresh_from_netbox(client)

    assert count == 2
    assert await store.get_cve_monitoring_off() == {"imported:57", "vm:3"}


async def test_managed_payload_stamps_cve_monitoring(fake_redis):
    await store.save_snapshot(
        [{"host_id": "device:12", "name": "a"}, {"host_id": "vm:3", "name": "b"}],
        {}, {}, [])
    await store.set_cve_monitoring(["vm:3"], False)

    payload = await store.get_managed_payload()
    flags = {h["host_id"]: h["cve_monitoring"] for h in payload["hosts"]}
    assert flags == {"device:12": True, "vm:3": False}
