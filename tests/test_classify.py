from app.services.classify import is_private_ipv4, site_for_ip


def test_rfc1918_accepted():
    assert is_private_ipv4("10.0.0.1")
    assert is_private_ipv4("172.16.5.9")
    assert is_private_ipv4("172.31.255.255")
    assert is_private_ipv4("192.168.1.1")


def test_public_and_special_rejected():
    assert not is_private_ipv4("8.8.8.8")
    assert not is_private_ipv4("127.0.0.1")       # loopback
    assert not is_private_ipv4("169.254.1.1")     # link-local
    assert not is_private_ipv4("224.0.0.5")       # multicast
    assert not is_private_ipv4("172.32.0.1")      # just outside 172.16/12


def test_non_ip_ids_rejected():
    assert not is_private_ipv4("fw01.acme.net")   # hostname
    assert not is_private_ipv4("jsmith")          # user id turned host
    assert not is_private_ipv4("")
    assert not is_private_ipv4("10.0.0.0/24")     # CIDR string
    assert not is_private_ipv4("fe80::1")         # IPv6


def test_site_longest_prefix_match():
    prefixes = [
        {"prefix": "10.250.47.0/27", "site": "lon8", "site_name": "LON8"},
        {"prefix": "10.0.0.0/8", "site": "global", "site_name": "Global"},
    ]
    assert site_for_ip("10.250.47.10", prefixes) == {"site": "lon8", "site_name": "LON8"}
    assert site_for_ip("10.1.2.3", prefixes) == {"site": "global", "site_name": "Global"}
    assert site_for_ip("192.168.1.1", prefixes) is None
    assert site_for_ip("not-an-ip", prefixes) is None
