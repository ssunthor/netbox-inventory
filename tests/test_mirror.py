import json

import respx
from httpx import Response

from app.services import netbox_mirror, store


def _page(results):
    return {"results": results, "next": None}


DEVICE_HOST = {
    "kind": "device", "id": 12, "host_id": "device:12",
    "name": "fw01.acme.net", "model": "PA-440", "manufacturer": "Palo Alto",
    "role": "Firewall", "site": "LON8", "status": "Active",
    "primary_ip": "10.250.47.10/27", "serial": "S123", "platform": None,
    "os_version": "9.1.3", "tags": [], "ips": ["10.250.47.10"],
    "cidrs": {"10.250.47.10": "10.250.47.10/27"},
}

VM_HOST = {
    "kind": "vm", "id": 7, "host_id": "vm:7",
    "name": "app01", "cluster": "prod", "role": "App", "site": "LON8",
    "status": "Active", "primary_ip": "10.250.47.20/27", "platform": None,
    "os_version": None, "vcpus": 4, "memory": 8192, "disk": 100,
    "tags": [], "ips": ["10.250.47.20"],
}


async def _seed_nbids(mapping: dict):
    for key, nbid in mapping.items():
        await store.set_nbid(key, nbid)


@respx.mock
async def test_mirror_creates_device(fake_redis):
    respx.get("http://netbox.test/api/extras/tags/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/extras/tags/").mock(
        return_value=Response(201, json={"id": 14}))
    respx.get("http://netbox.test/api/dcim/manufacturers/").mock(
        return_value=Response(200, json=_page([{"id": 12}])))
    respx.get("http://netbox.test/api/dcim/device-types/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/device-types/").mock(
        return_value=Response(201, json={"id": 13}))
    respx.get("http://netbox.test/api/dcim/device-roles/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/device-roles/").mock(
        return_value=Response(201, json={"id": 11}))
    respx.get("http://netbox.test/api/dcim/sites/").mock(
        return_value=Response(200, json=_page([{"id": 21}])))
    respx.get("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([])))  # no same-named object
    device_create = respx.post("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(201, json={"id": 100}))
    respx.get("http://netbox.test/api/dcim/interfaces/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/dcim/interfaces/").mock(
        return_value=Response(201, json={"id": 200}))
    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([])))
    ip_create = respx.post("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(201, json={"id": 300}))
    primary_patch = respx.patch("http://netbox.test/api/dcim/devices/100/").mock(
        return_value=Response(200, json={"id": 100}))

    result = await netbox_mirror.mirror_managed_hosts([dict(DEVICE_HOST)])

    assert result["created"] == 1 and result["failed"] == 0
    body = json.loads(device_create.calls[0].request.content)
    assert body["name"] == "fw01.acme.net"
    assert body["status"] == "active"       # label normalized to API value
    assert body["device_type"] == 13 and body["role"] == 11 and body["site"] == 21
    assert body["tenant"] == 1
    assert body["tags"] == [{"name": "halo-managed", "slug": "halo-managed"}]
    assert "Mirrored from GT-T NetBox (device:12)" in body["comments"]
    # Real CIDR from GT-T carried through, not a /32 host route
    assert json.loads(ip_create.calls[0].request.content)["address"] == "10.250.47.10/27"
    assert json.loads(primary_patch.calls[0].request.content) == {"primary_ip4": 300}
    mapping = await store.get_mirror_map()
    assert mapping["device:12"]["id"] == 100
    assert mapping["device:12"]["fp"] == netbox_mirror._fingerprint(DEVICE_HOST)


@respx.mock
async def test_mirror_creates_vm_with_cluster(fake_redis):
    await _seed_nbids({"tag:halo-managed": 14, "site:lon8": 21})
    respx.get("http://netbox.test/api/virtualization/clusters/").mock(
        return_value=Response(200, json=_page([{"id": 31}])))
    respx.get("http://netbox.test/api/virtualization/virtual-machines/").mock(
        return_value=Response(200, json=_page([])))
    vm_create = respx.post("http://netbox.test/api/virtualization/virtual-machines/").mock(
        return_value=Response(201, json={"id": 101}))
    respx.get("http://netbox.test/api/virtualization/interfaces/").mock(
        return_value=Response(200, json=_page([])))
    respx.post("http://netbox.test/api/virtualization/interfaces/").mock(
        return_value=Response(201, json={"id": 201}))
    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([])))
    ip_create = respx.post("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(201, json={"id": 301}))
    respx.patch("http://netbox.test/api/virtualization/virtual-machines/101/").mock(
        return_value=Response(200, json={"id": 101}))

    result = await netbox_mirror.mirror_managed_hosts([dict(VM_HOST)])

    assert result["created"] == 1 and result["failed"] == 0
    body = json.loads(vm_create.calls[0].request.content)
    assert body["cluster"] == 31 and body["site"] == 21
    assert body["vcpus"] == 4 and body["memory"] == 8192 and body["disk"] == 100
    ip_body = json.loads(ip_create.calls[0].request.content)
    assert ip_body["address"] == "10.250.47.20/32"  # no cidrs map -> /32 fallback
    assert ip_body["assigned_object_type"] == "virtualization.vminterface"


@respx.mock
async def test_mirror_unchanged_host_makes_no_api_calls(fake_redis):
    await _seed_nbids({"tag:halo-managed": 14})
    await store.set_mirror_entry("device:12", 100,
                                 netbox_mirror._fingerprint(DEVICE_HOST))

    # No respx routes registered: any HTTP call would fail the test.
    result = await netbox_mirror.mirror_managed_hosts([dict(DEVICE_HOST)])

    assert result["unchanged"] == 1
    assert result["created"] == result["updated"] == result["failed"] == 0


@respx.mock
async def test_mirror_adopts_existing_by_name_and_updates(fake_redis):
    await _seed_nbids({"tag:halo-managed": 14, "manufacturer:palo-alto": 12,
                       "devicetype:pa-440": 13, "role:firewall": 11,
                       "site:lon8": 21})
    respx.get("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([{"id": 55, "name": "fw01.acme.net"}])))
    device_patch = respx.patch("http://netbox.test/api/dcim/devices/55/").mock(
        return_value=Response(200, json={"id": 55}))
    respx.get("http://netbox.test/api/dcim/interfaces/").mock(
        return_value=Response(200, json=_page([{"id": 200}])))
    respx.get("http://netbox.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([
            {"id": 300, "address": "10.250.47.10/27",
             "assigned_object_type": "dcim.interface",
             "assigned_object_id": 200}])))

    result = await netbox_mirror.mirror_managed_hosts([dict(DEVICE_HOST)])

    assert result["updated"] == 1 and result["created"] == 0
    body = json.loads(device_patch.calls[0].request.content)
    assert body["device_type"] == 13 and "comments" not in body
    mapping = await store.get_mirror_map()
    assert mapping["device:12"]["id"] == 55  # adopted, now tracked


@respx.mock
async def test_mirror_400_counts_failed_and_surfaces_body(fake_redis, caplog):
    await _seed_nbids({"tag:halo-managed": 14, "manufacturer:palo-alto": 12,
                       "devicetype:pa-440": 13, "role:firewall": 11,
                       "site:lon8": 21})
    respx.get("http://netbox.test/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([{"id": 9, "name": "fw01.acme.net"}])))
    respx.patch("http://netbox.test/api/dcim/devices/9/").mock(
        return_value=Response(400, json={"tags": ["Expected a dictionary"]}))

    result = await netbox_mirror.mirror_managed_hosts([dict(DEVICE_HOST)])

    assert result["failed"] == 1 and result["error"] is None  # not fatal
    assert await store.get_mirror_map() == {}  # failed host stays untracked
    assert "Expected a dictionary" in caplog.text  # NetBox body in the log


@respx.mock
async def test_mirror_retires_hosts_dropped_from_gtt(fake_redis):
    await _seed_nbids({"tag:halo-managed": 14})
    await store.set_mirror_entry("device:99", 70, "stale-fp")

    retire_patch = respx.patch("http://netbox.test/api/dcim/devices/70/").mock(
        return_value=Response(200, json={"id": 70}))

    result = await netbox_mirror.mirror_managed_hosts([])

    assert result["retired"] == 1
    assert json.loads(retire_patch.calls[0].request.content) == {"status": "offline"}
    assert await store.get_mirror_map() == {}  # tracking entry removed
