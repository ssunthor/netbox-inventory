import ipaddress
import re

RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_private_ipv4(value: str) -> bool:
    """True only for RFC1918 IPv4 addresses — the sole class of host id
    eligible for NetBox registration. Hostnames, user ids, public and
    special-purpose addresses (loopback, link-local, multicast) all fail."""
    if not value or not RE_IPV4.match(value):
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


def site_for_ip(ip: str, prefixes: list[dict]) -> dict | None:
    """Longest-prefix match. `prefixes` must already be sorted by prefix
    length descending (netbox_sync guarantees this)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for entry in prefixes:
        try:
            if addr in ipaddress.ip_network(entry["prefix"], strict=False):
                return {"site": entry["site"], "site_name": entry["site_name"]}
        except (KeyError, ValueError):
            continue
    return None
