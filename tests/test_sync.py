import respx
from httpx import Response

from app.services import netbox, netbox_sync, store


def _page(results, next_url=None):
    return {"results": results, "next": next_url}


DEVICE = {
    "id": 12, "name": "fw01.acme.net",
    "device_type": {"model": "PA-440", "manufacturer": {"name": "Palo Alto"}},
    "role": {"name": "Firewall"}, "site": {"name": "LON8"},
    "status": {"label": "Active"},
    "primary_ip4": {"address": "10.250.47.10/27"},
    "custom_fields": {"os_build": "9.1.3"},
    "tags": [],
}

VM = {
    "id": 7, "name": "app01",
    "cluster": {"name": "prod"}, "role": {"name": "App"},
    "site": {"name": "LON8"}, "status": {"label": "Active"},
    "primary_ip4": {"address": "10.250.47.20/27"},
    "vcpus": 4, "memory": 8192, "disk": 100, "tags": [],
}


@respx.mock
async def test_gtt_tenant_scoping(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "GTT_NETBOX_TENANT_ID", 42)
    devices = respx.get("http://gtt.test/api/dcim/devices/").mock(
        return_value=Response(200, json=_page([])))
    vms = respx.get("http://gtt.test/api/virtualization/virtual-machines/").mock(
        return_value=Response(200, json=_page([])))
    ips = respx.get("http://gtt.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([])))

    await netbox.fetch_managed_hosts_from_gtt()
    for route in (devices, vms, ips):
        assert route.calls[0].request.url.params["tenant_id"] == "42"

    # Unset -> falls back to NETBOX_TENANT_ID (1 in conftest)
    monkeypatch.setattr(settings, "GTT_NETBOX_TENANT_ID", None)
    await netbox.fetch_managed_hosts_from_gtt()
    for route in (devices, vms, ips):
        assert route.calls[-1].request.url.params["tenant_id"] == "1"


def test_rebase_forces_configured_scheme_and_host():
    assert netbox._rebase("http://netbox.example.com/api/dcim/devices/?offset=50",
                          "https://netbox.example.com") == \
        "https://netbox.example.com/api/dcim/devices/?offset=50"
    assert netbox._rebase(None, "https://netbox.example.com") is None


@respx.mock
async def test_gtt_fetch_pagination_and_interface_ips():
    # Page 1's "next" link deliberately uses https while the base is http —
    # _rebase must pull it back onto the configured scheme/host.
    respx.get("http://gtt.test/api/dcim/devices/").mock(side_effect=[
        Response(200, json=_page([DEVICE], "https://gtt.test/api/dcim/devices/?offset=1")),
        Response(200, json=_page([{**DEVICE, "id": 13, "name": "fw02", "primary_ip4": None,
                                   "custom_fields": {"os_build": "None"}}])),
    ])
    respx.get("http://gtt.test/api/virtualization/virtual-machines/").mock(
        return_value=Response(200, json=_page([VM])))
    respx.get("http://gtt.test/api/ipam/ip-addresses/").mock(
        return_value=Response(200, json=_page([
            {"address": "10.250.47.11/27", "assigned_object_type": "dcim.interface",
             "assigned_object": {"device": {"id": 12}}},
            {"address": "10.250.47.21/27", "assigned_object_type": "virtualization.vminterface",
             "assigned_object": {"virtual_machine": {"id": 7}}},
            {"address": "10.9.9.9/32", "assigned_object_type": None, "assigned_object": None},
        ])))

    hosts = await netbox.fetch_managed_hosts_from_gtt()
    assert len(hosts) == 3  # pagination followed: 2 devices + 1 vm
    fw01 = next(h for h in hosts if h["host_id"] == "device:12")
    assert sorted(fw01["ips"]) == ["10.250.47.10", "10.250.47.11"]
    assert fw01["cidrs"] == {"10.250.47.10": "10.250.47.10/27",
                             "10.250.47.11": "10.250.47.11/27"}
    assert fw01["os_version"] == "9.1.3"  # custom_fields.os_build, for CVE scans
    fw02 = next(h for h in hosts if h["host_id"] == "device:13")
    assert fw02["os_version"] is None  # literal "None" placeholder scrubbed
    vm = next(h for h in hosts if h["host_id"] == "vm:7")
    assert sorted(vm["ips"]) == ["10.250.47.20", "10.250.47.21"]

    ip_index, name_index = netbox.build_indexes(hosts)
    assert ip_index["10.250.47.11"] == "device:12"
    assert name_index["fw01.acme.net"] == "device:12"
    assert name_index["fw01"] == "device:12"  # short name too
    assert name_index["app01"] == "vm:7"


@respx.mock
async def test_prefix_fetch_scope_priority_and_sort():
    respx.get("http://netbox.test/api/ipam/prefixes/").mock(
        return_value=Response(200, json=_page([
            {"prefix": "10.0.0.0/8", "scope": None, "site": {"name": "Global", "slug": "global"}},
            {"prefix": "10.250.47.0/27", "scope": {"name": "LON8", "slug": "lon8"}},
            {"prefix": "10.1.0.0/16", "scope": None, "site": None,
             "tenant": {"name": "Acme Corp"}},
            {"prefix": "bogus", "scope": {"name": "X"}},
            {"prefix": "10.2.0.0/16"},  # no scope/site/tenant -> skipped
        ])))
    prefixes = await netbox.fetch_prefixes_from_customer()
    assert [p["prefix"] for p in prefixes] == ["10.250.47.0/27", "10.1.0.0/16", "10.0.0.0/8"]
    assert prefixes[1]["site"] == "acme-corp"  # slugified tenant fallback


async def test_run_sync_failure_keeps_last_good(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "MIRROR_ENABLED", False)

    async def good():
        return [dict(DEVICE_NORM)]

    async def good_prefixes():
        return [{"prefix": "10.0.0.0/8", "site": "global", "site_name": "Global"}]

    DEVICE_NORM = {"kind": "device", "id": 12, "host_id": "device:12",
                   "name": "fw01", "ips": ["10.250.47.10"]}
    monkeypatch.setattr(netbox, "fetch_managed_hosts_from_gtt", good)
    monkeypatch.setattr(netbox, "fetch_prefixes_from_customer", good_prefixes)

    result = await netbox_sync.run_sync()
    assert result["ok"] and result["version"] == 1

    async def boom():
        raise RuntimeError("gtt unreachable")

    monkeypatch.setattr(netbox, "fetch_managed_hosts_from_gtt", boom)
    result = await netbox_sync.run_sync()
    assert not result["ok"]

    payload = await store.get_managed_payload()
    assert payload["stale"] is True
    assert payload["version"] == 1
    assert payload["hosts"][0]["host_id"] == "device:12"  # last-good preserved
    assert payload["ip_index"] == {"10.250.47.10": "device:12"}


async def test_run_sync_mirrors_managed_set(monkeypatch):
    from app.services import netbox_mirror

    hosts = [{"kind": "device", "id": 12, "host_id": "device:12",
              "name": "fw01", "ips": ["10.250.47.10"]}]

    async def good():
        return list(hosts)

    async def no_prefixes():
        return []

    mirrored = []

    async def fake_mirror(passed_hosts):
        mirrored.append(passed_hosts)
        return {"created": 1, "updated": 0, "unchanged": 0,
                "retired": 0, "failed": 0, "error": None}

    monkeypatch.setattr(netbox, "fetch_managed_hosts_from_gtt", good)
    monkeypatch.setattr(netbox, "fetch_prefixes_from_customer", no_prefixes)
    monkeypatch.setattr(netbox_mirror, "mirror_managed_hosts", fake_mirror)

    result = await netbox_sync.run_sync()
    assert result["ok"]
    assert result["mirror"]["created"] == 1
    assert mirrored == [hosts]  # mirror received the synced host set
