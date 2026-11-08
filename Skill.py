"""
skill.py — RESTCONF skill implementation
Project: ARS110_HT26_RestConf_GruppX
Skill: Full network configuration (interfaces, RIP, ACL)

Structure — one API call per logical config item (no single "native:native" PUT):
    Part 1: ISPN Loopback0             (ietf-interfaces)
    Part 2: ISPN Serial0/1/0           (Cisco-IOS-XE-native — Serial has poor IETF support)
    Part 3: JUNK Serial0/1/0           (Cisco-IOS-XE-native)
    Part 4: JUNK GigabitEthernet0/0/0  (ietf-interfaces)
    Part 5/6: RIP on both routers      (native — PUT to create process, PATCH per network)
    Part 7: ACL on JUNK                (native Cisco-IOS-XE-acl)
    Part 7b: Bind ACL to interface     (native access-group)

AUTH NOTE (documented in report):
    - Token auth via /api/v1/auth/token-services → 411 (nginx rejects)
    - Token auth via /dna/system/api/v1/auth/token → 404 (not exposed)
    - mTLS with client cert + trustpoint + clientAuth EKU → 401
    - Fallback: Basic Auth over HTTPS with verify=False (lab only)
"""

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

# ─── Device registry ─────────────────────────────────────────
DEVICES = {
    "ISPN": {
        "host": "192.168.130.5",
        "username": "admin",
        "password": "class",
        "use_cert": False,
    },
    "JUNK": {
        "host": "192.168.130.6",
        "username": "admin",
        "password": "class",
        "use_cert": False,
    },
}

CERT = (
    r"C:\Users\cisco\Documents\Rest-Conf\Certs\client.crt",
    r"C:\Users\cisco\Documents\Rest-Conf\Certs\client.key",
)

HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def restconf(device_name, method, path, payload=None, label=""):
    """Fire one RESTCONF call. Returns requests.Response or None."""
    device = DEVICES[device_name]
    url = f"https://{device['host']}/restconf/data/{path}"
    tag = f"[{device_name}] {label or method}"

    kwargs = {
        "headers": HEADERS,
        "json": payload,
        "verify": False,
        "timeout": 15,
    }

    if device["use_cert"]:
        kwargs["cert"] = CERT
    else:
        kwargs["auth"] = (device["username"], device["password"])

    try:
        r = requests.request(method, url, **kwargs)
        ok = 200 <= r.status_code < 300
        print(f"  {'OK ' if ok else 'ERR'} {tag}: {r.status_code}")
        if not ok:
            print(f"      {r.text[:250]}")
        return r
    except requests.RequestException as e:
        print(f"  ERR {tag}: {e}")
        return None


# ═══ Part 1: ISPN Loopback0 (ietf-interfaces) ═══════════════
def config_ispn_loopback():
    print("\n[Part 1] ISPN Loopback0 — 192.168.128.129/25")
    payload = {
        "ietf-interfaces:interface": {
            "name": "Loopback0",
            "description": "Internet",
            "type": "iana-if-type:softwareLoopback",
            "enabled": True,
            "ietf-ip:ipv4": {
                "address": [
                    {"ip": "192.168.128.129", "netmask": "255.255.255.128"}
                ]
            },
        }
    }
    restconf("ISPN", "PUT",
             "ietf-interfaces:interfaces/interface=Loopback0",
             payload, "Loopback0")


# ═══ Part 2: ISPN Serial0/1/0 (native) ═════════════════════
def config_ispn_serial():
    print("\n[Part 2] ISPN Serial0/1/0 — 192.168.129.1/30")
    payload = {
        "Cisco-IOS-XE-native:Serial": {
            "name": "0/1/0",
            "description": "ISPN to JUNK",
            "ip": {
                "address": {
                    "primary": {
                        "address": "192.168.129.1",
                        "mask": "255.255.255.252",
                    }
                }
            },
        }
    }
    restconf("ISPN", "PUT",
             "Cisco-IOS-XE-native:native/interface/Serial=0%2F1%2F0",
             payload, "Serial0/1/0")


# ═══ Part 3: JUNK Serial0/1/0 (native) ═════════════════════
def config_junk_serial():
    print("\n[Part 3] JUNK Serial0/1/0 — 192.168.129.2/30")
    payload = {
        "Cisco-IOS-XE-native:Serial": {
            "name": "0/1/0",
            "description": "JUNK to ISPN",
            "ip": {
                "address": {
                    "primary": {
                        "address": "192.168.129.2",
                        "mask": "255.255.255.252",
                    }
                }
            },
        }
    }
    restconf("JUNK", "PUT",
             "Cisco-IOS-XE-native:native/interface/Serial=0%2F1%2F0",
             payload, "Serial0/1/0")


# ═══ Part 4: JUNK GigabitEthernet0/0/0 (ietf-interfaces) ═══
def config_junk_lan():
    print("\n[Part 4] JUNK GigabitEthernet0/0/0 — 192.168.130.1/24")
    payload = {
        "ietf-interfaces:interface": {
            "name": "GigabitEthernet0/0/0",
            "description": "JUNK LAN",
            "type": "iana-if-type:ethernetCsmacd",
            "enabled": True,
            "ietf-ip:ipv4": {
                "address": [
                    {"ip": "192.168.130.1", "netmask": "255.255.255.0"}
                ]
            },
        }
    }
    restconf("JUNK", "PUT",
             "ietf-interfaces:interfaces/interface=GigabitEthernet0%2F0%2F0",
             payload, "GigabitEthernet0/0/0")


# ═══ Parts 5-6: RIP on each router (native) ════════════════
def config_rip(device_name, networks):
    print(f"\n[Part 5/6] RIP on {device_name} — networks: {networks}")
    path = "Cisco-IOS-XE-native:native/router/Cisco-IOS-XE-rip:rip"

    # ── Step 1: CREATE the RIP process with PUT (PATCH fails 404 if absent) ──
    restconf(device_name, "PUT", path,
             {"Cisco-IOS-XE-rip:rip": {"version": 2}},
             "create RIP process (version 2)")

    # ── Step 2: ADD each network with PATCH (process now exists) ──
    for net in networks:
        restconf(device_name, "PATCH", path,
                 {"Cisco-IOS-XE-rip:rip": {"network": [{"ip": net}]}},
                 f"network {net}")


# ═══ Part 7: ACL on JUNK (native Cisco-IOS-XE-acl) ═════════
def config_junk_acl():
    print("\n[Part 7] JUNK ACL — block Per_PC from ISP Loopback:80")

    acl_path = (
        "Cisco-IOS-XE-native:native/ip/access-list/"
        "Cisco-IOS-XE-acl:extended=BLOCK_WEB"
    )

    acl_payload = {
        "Cisco-IOS-XE-acl:extended": {
            "name": "BLOCK_WEB",
            "access-list-seq-rule": [
                {
                    "sequence": "10",
                    "ace-rule": {
                        "action": "deny",
                        "protocol": "tcp",
                        "ipv4-address": "192.168.130.10",
                        "mask": "0.0.0.0",
                        "dest-ipv4-address": "192.168.128.129",
                        "dest-mask": "0.0.0.0",
                        "dst-eq": 80,
                    },
                },
                {
                    "sequence": "20",
                    "ace-rule": {
                        "action": "permit",
                        "protocol": "tcp",
                        "ipv4-address": "192.168.130.20",
                        "mask": "0.0.0.0",
                        "dest-ipv4-address": "192.168.128.129",
                        "dest-mask": "0.0.0.0",
                        "dst-eq": 80,
                    },
                },
                {
                    "sequence": "30",
                    "ace-rule": {
                        "action": "permit",
                        "protocol": "ip",
                        "any": [None],
                        "dst-any": [None],
                    },
                },
            ],
        }
    }

    restconf("JUNK", "PUT", acl_path, acl_payload, "define ACL BLOCK_WEB")


# ═══ Part 7b: Bind ACL to JUNK LAN interface ═══════════════
def apply_acl_to_interface():
    print("\n[Part 7b] Bind ACL to JUNK G0/0/0 inbound")
    path = (
        "Cisco-IOS-XE-native:native/interface/"
        "GigabitEthernet=0%2F0%2F0/ip/access-group"
    )
    payload = {
        "Cisco-IOS-XE-native:access-group": {
            "in": {
                "acl": {
                    "acl-name": "BLOCK_WEB",
                    "in": [None],
                }
            }
        }
    }
    restconf("JUNK", "PATCH", path, payload, "apply ACL inbound")


# ═══ Main ═══════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("skill.py — applying network configuration via RESTCONF")
    print("=" * 60)

    config_ispn_loopback()
    config_ispn_serial()
    config_junk_serial()
    config_junk_lan()

    config_rip("ISPN", ["192.168.128.0", "192.168.129.0"])
    config_rip("JUNK", ["192.168.129.0", "192.168.130.0"])

    config_junk_acl()
    apply_acl_to_interface()

    print("\n" + "=" * 60)
    print("Done. Run robert.py to grade the result.")
    print("=" * 60)


if __name__ == "__main__":
    main()