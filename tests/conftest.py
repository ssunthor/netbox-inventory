import os

# Must be set before anything imports app.config
os.environ.update({
    "NETBOX_URL": "http://netbox.test",
    "NETBOX_TOKEN": "customer-token",
    "NETBOX_CUSTOMER_NAME": "Test Corp",
    "NETBOX_TENANT_ID": "1",
    "GTT_NETBOX_URL": "http://gtt.test",
    "GTT_NETBOX_TOKEN": "gtt-token",
    "CMD_API_URL": "http://cmd.test/v1/graphql",
    "CMD_TOKEN_URL": "http://cmd.test/token",
    "CMD_CLIENT_ID": "cid",
    "CMD_CLIENT_SECRET": "secret",
    "CMD_SCOPE": "read",
})

import fakeredis.aioredis  # noqa: E402
import pytest  # noqa: E402

import app.services.store as store_module  # noqa: E402


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(store_module, "redis", r)
    yield r
