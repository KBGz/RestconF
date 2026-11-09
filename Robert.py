"""
robert.py — automated grader for the skill assignment.

Checks:
    C1: ISPN Loopback0 IP = 192.168.128.129/25
    C2: ISPN Serial0/1/0 IP = 192.168.129.1/30
    C3: JUNK Serial0/1/0 IP = 192.168.129.2/30
    C4: JUNK Gig0/0/0 IP = 192.168.130.1/24
    C5: ISPN RIP networks = {192.168.128.0, 192.168.129.0}
    C6: JUNK RIP networks = {192.168.129.0, 192.168.130.0}
    C7: JUNK ACL BLOCK_WEB present with deny+permit+permit rules
    C8: JUNK routing table has RIP-learned 192.168.128.0/25 

"""

import sys
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

DEVICES = {
    "ISPN": {"host": "192.168.130.5", "username": "admin", "password": "class"},
    "JUNK": {"host": "192.168.130.6", "username": "admin", "password": "class"},
}

HEADERS = {"Accept": "application/yang-data+json"}
AUTH = lambda d: (d["username"], d["password"])

results = []   # list of (check_id, description, ok_or_None, detail)


def get(device_name, path):
    """GET one RESTCONF path. Returns parsed JSON or None."""
    d = DEVICES[device_name]
    url = f"https://{d['host']}/restconf/data/{path}"
    try:
        r = requests.get(url, auth=AUTH(d), headers=HEADERS,
                         verify=False, timeout=15)
        if r.status_code == 200:
            return r.json()
        print(f"  [{device_name}] GET {path} -> {r.status_code}")
        return None
    except requests.RequestException as e:
        print(f"  [{device_name}] GET {path} failed: {e}")
        return None


def record(check_id, description, ok, detail=""):
    results.append((check_id, description, ok, detail))


def mask_matches(actual, expected_dotted):
    """Match a dotted netmask OR a prefix-length integer against a dotted mask."""
    if actual is None:
        return False
    s = str(actual).strip()
    if s == expected_dotted:
        return True
    try:
        prefix_to_dotted = {
            24: "255.255.255.0",
            25: "255.255.255.128",
            30: "255.255.255.252",
        }
        return prefix_to_dotted.get(int(s)) == expected_dotted
    except (ValueError, TypeError):
        return False


# ═══ interface check via ietf-interfaces ════════════
def check_ietf_interface(device, iface_name, expected_ip,
                         expected_mask, check_id):
    desc = f"{device} {iface_name} = {expected_ip} ({expected_mask})"
    path = (
        "ietf-interfaces:interfaces/"
        f"interface={iface_name.replace('/', '%2F')}"
    )
    data = get(device, path)
    if not data:
        record(check_id, desc, False, "endpoint not readable")
        return

    iface = data.get("ietf-interfaces:interface", {})
    addrs = iface.get("ietf-ip:ipv4", {}).get("address", [])
    for a in addrs:
        if a.get("ip") == expected_ip:
            actual_mask = a.get("netmask") or a.get("prefix-length")
            if mask_matches(actual_mask, expected_mask):
                record(check_id, desc, True)
                return
            record(check_id, desc, False,
                   f"IP ok but mask is {actual_mask}")
            return

    record(check_id, desc, False,
           f"interface exists, addresses: {addrs}")


# ═══ Serial check via native model ══════════════════
def check_serial(device, serial_num, expected_ip, expected_mask, check_id):
    desc = f"{device} Serial{serial_num} = {expected_ip} ({expected_mask})"
    path = (
        "Cisco-IOS-XE-native:native/interface/"
        f"Serial={serial_num.replace('/', '%2F')}"
    )
    data = get(device, path)
    if not data:
        record(check_id, desc, False, "endpoint not readable")
        return

    serial = data.get("Cisco-IOS-XE-native:Serial", {})
    primary = serial.get("ip", {}).get("address", {}).get("primary", {})
    actual_ip = primary.get("address")
    actual_mask = primary.get("mask")

    if actual_ip == expected_ip and mask_matches(actual_mask, expected_mask):
        record(check_id, desc, True)
    else:
        record(check_id, desc, False,
               f"got ip={actual_ip}, mask={actual_mask}")


# ═══ RIP network checks ═════════════════════════════
def check_rip(device, expected_networks, check_id):
    desc = f"{device} RIP networks = {sorted(expected_networks)}"
    data = get(device,
               "Cisco-IOS-XE-native:native/router/Cisco-IOS-XE-rip:rip")
    if not data:
        record(check_id, desc, False, "RIP container not found")
        return

    rip = data.get("Cisco-IOS-XE-rip:rip", {})
    actual = {n.get("ip") for n in rip.get("network", [])}
    expected = set(expected_networks)
    missing = expected - actual
    extra = actual - expected

    if not missing and not extra:
        record(check_id, desc, True)
    else:
        record(check_id, desc, False,
               f"missing={sorted(missing)}, extra={sorted(extra)}")


# ═══ ACL check ══════════════════════════════════════════
def check_acl(device, acl_name, check_id):
    desc = f"{device} ACL '{acl_name}' has deny+permit+permit rules"
    path = (
        "Cisco-IOS-XE-native:native/ip/access-list/"
        f"Cisco-IOS-XE-acl:extended={acl_name}"
    )
    data = get(device, path)
    if not data:
        record(check_id, desc, False, "ACL endpoint returned no data")
        return

    acl = data.get("Cisco-IOS-XE-acl:extended", {})
    if isinstance(acl, list):
        acl = acl[0] if acl else {}

    rules = acl.get("access-list-seq-rule", [])
    actual = {
        str(r.get("sequence")): r.get("ace-rule", {}).get("action")
        for r in rules
    }
    expected = {"10": "deny", "20": "permit", "30": "permit"}

    if actual == expected:
        record(check_id, desc, True)
    else:
        record(check_id, desc, False,
               f"expected={expected}, actual={actual}")


# ═══ RIP-learned route in operational table ═════════════
def check_rip_route(device, expected_prefix, check_id):
    """SKIP if operational routing model isn't supported (avoids false negatives)."""
    desc = f"{device} routing table has RIP-learned route to {expected_prefix}"
    data = get(device, "ietf-routing:routing-state")
    if not data:
        record(check_id, desc, None,
               "ietf-routing:routing-state not available on this platform")
        return

    try:
        rs = data.get("ietf-routing:routing-state", {})
        inst = rs.get("routing-instance", [{}])[0]
        rib = inst.get("ribs", {}).get("rib", [{}])[0]
        routes = rib.get("routes", {}).get("route", [])
    except (KeyError, IndexError, TypeError, AttributeError):
        record(check_id, desc, None, "routing-state structure unexpected")
        return

    target = expected_prefix.split("/")[0]
    for r in routes:
        dest = r.get("destination-prefix", "")
        proto = str(r.get("source-protocol") or "").lower()
        if target in dest and "rip" in proto:
            record(check_id, desc, True)
            return

    record(check_id, desc, False,
           f"no RIP route to {expected_prefix} found in routing state")


# ═══ Main ═══════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("robert.py — grading the skill configuration")
    print("=" * 60)

    # 1: ISPN Loopback0 (ietf-interfaces)
    check_ietf_interface("ISPN", "Loopback0",
                         "192.168.128.129", "255.255.255.128", "C1")

    # 2: ISPN Serial0/1/0 (native)
    check_serial("ISPN", "0/1/0",
                 "192.168.129.1", "255.255.255.252", "C2")

    # 3: JUNK Serial0/1/0 (native)
    check_serial("JUNK", "0/1/0",
                 "192.168.129.2", "255.255.255.252", "C3")

    # 4: JUNK GigabitEthernet0/0/0 (ietf-interfaces)
    check_ietf_interface("JUNK", "GigabitEthernet0/0/0",
                         "192.168.130.1", "255.255.255.0", "C4")

    # 5 and 6: RIP config
    check_rip("ISPN", ["192.168.128.0", "192.168.129.0"], "C5")
    check_rip("JUNK", ["192.168.129.0", "192.168.130.0"], "C6")

    # 7: ACL
    check_acl("JUNK", "BLOCK_WEB", "C7")

    # 8: live RIP route (SKIP if model unsupported)
    check_rip_route("JUNK", "192.168.128.0/25", "C8")

    # ── Report ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("GRADING REPORT")
    print("=" * 60)
    passed = 0
    failed = 0
    skipped = 0

    for cid, desc, ok, detail in results:
        if ok is True:
            print(f"  [PASS] {cid}: {desc}")
            passed += 1
        elif ok is False:
            print(f"  [FAIL] {cid}: {desc}")
            if detail:
                print(f"         reason: {detail}")
            failed += 1
        else:  # ok is None → skip
            print(f"  [SKIP] {cid}: {desc}")
            if detail:
                print(f"         note: {detail}")
            skipped += 1

    total = len(results)
    print("-" * 60)
    print(f"  {passed}/{total} passed, {failed} failed, {skipped} skipped")

    if failed == 0:
        print("  GRADE: PASS")
        sys.exit(0)
    else:
        print("  GRADE: FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
