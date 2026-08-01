#!/usr/bin/env python3
import json, argparse, subprocess, sys

sh = lambda c: subprocess.run(c, shell=True, text=True, capture_output=True)

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------
ap = argparse.ArgumentParser()
ap.add_argument("--graph", required=True)
ap.add_argument("--ifmap", required=True)
ap.add_argument("--node",  required=True)
args = ap.parse_args()

me = args.node
ifmap = json.load(open(args.ifmap))
topo = json.load(open(args.graph))

# Rebuild easy lookup structures
nodes = {n["id"]: n for n in topo["nodes"]}
links = topo["links"]

role = nodes[me]["role"].lower()
asn  = int(nodes[me]["asn"])
my_lo = nodes[me]["lo_v6"].split("/")[0]

# ------------------------------------------------------------
# CORE ROUTERS → action End (main table only)
# ------------------------------------------------------------
if role in ("core1", "core2"):
    sh(f"ip -6 route replace {my_lo}/128 encap seg6local action End dev lo")
    print(f"{me}: installed End SID for {my_lo}")
    sys.exit(0)

# ------------------------------------------------------------
# ACCESS / EDGE ONLY
# ------------------------------------------------------------
if role not in ("edge", "access"):
    print(f"{me}: no SRv6 actions for role {role}")
    sys.exit(0)

# ------------------------------------------------------------
# Build ip→node map (loopback + link interface addrs)
# ------------------------------------------------------------
ip_to_node = {}

for nid, n in nodes.items():
    lo = n.get("lo_v6")
    if lo:
        ip_to_node[lo.split("/")[0]] = nid

for e in links:
    for nid, ip in (e.get("ip_map_v6") or {}).items():
        ip_to_node[ip.split("/")[0]] = nid

# ------------------------------------------------------------
# Find core1 & core2 for this AS
# ------------------------------------------------------------
core1 = core2 = None
for nid, nd in nodes.items():
    if int(nd["asn"]) != asn:
        continue
    r = nd["role"].lower()
    if r == "core1": core1 = nid
    if r == "core2": core2 = nid

if not core1 or not core2:
    print(f"{me}: ERROR – missing core1/core2 for AS{asn}")
    sys.exit(1)

c1_lo = nodes[core1]["lo_v6"].split("/")[0]
c2_lo = nodes[core2]["lo_v6"].split("/")[0]

# ------------------------------------------------------------
# Interface lookup using ifmap
#    -> now returns (dev, core_link_ip)
# ------------------------------------------------------------
def iface_to(peer):
    for e in links:
        u, v = e["source"], e["target"]
        if {u, v} == {me, peer}:
            net = e.get("net_name") or e.get("lan")
            dev = ifmap.get(net)
            ipm = e.get("ip_map_v6") or {}
            core_ip = ipm.get(peer, "").split("/")[0]
            return dev, core_ip
    return None, None

d1, c1_on = iface_to(core1)
d2, c2_on = iface_to(core2)

if not d1 or not d2:
    print(f"{me}: ERROR – cannot find interfaces to cores")
    sys.exit(1)

# ------------------------------------------------------------
# Install End.DT6 for self (main + table100)
# ------------------------------------------------------------
sh(f"ip -6 route replace {my_lo}/128 encap seg6local action End.DT6 dev lo")
sh(f"ip -6 route replace {my_lo}/128 encap seg6local action End.DT6 dev lo table 100")

# ------------------------------------------------------------
# NEW: static reachability to core1 loopback in table 100
# ------------------------------------------------------------

print()
print("=== DEBUG: core1 static route installation ===")
print(f"core1 loopback  (c1_lo): {c1_lo}")
print(f"core1 link-ip   (c1_on): {c1_on}")
print(f"interface to c1 (d1):    {d1}")
print()

if not c1_on:
    print("❌ ERROR: core1 link-ip (c1_on) is EMPTY — cannot install route")
elif not d1:
    print("❌ ERROR: interface to core1 (d1) is EMPTY — cannot install route")
else:
    cmd = (
        f"ip -6 route replace {c1_lo}/128 "
        f"via {c1_on} dev {d1} table 100"
    )
    print(f"Running command:\n  {cmd}\n")

    res = sh(cmd)

    print(f"Return code: {res.returncode}")
    if res.stderr.strip():
        print(f"stderr:\n{res.stderr}")
    if res.stdout.strip():
        print(f"stdout:\n{res.stdout}")

    if res.returncode == 0:
        print("👍 SUCCESS: route installed.")
    else:
        print("❌ FAILURE: route not installed.")
print("=== END DEBUG ===")
print()

# ============================================================
# NEW BGP LOGIC (ONLY CHANGED SECTION)
# ============================================================

# ---- DEFAULT TABLE ----
out0 = sh("vtysh -c 'show ipv6 route bgp json'")
rib0 = json.loads(out0.stdout) if (out0.returncode == 0 and out0.stdout.strip()) else {}

# ---- TABLE 100 ----
out100 = sh("vtysh -c 'show ipv6 route table 100 bgp json'")
rib100 = json.loads(out100.stdout) if (out100.returncode == 0 and out100.stdout.strip()) else {}

count = 0

def install_srv6_from_rib(rib, table_id, core_lo, iface):
    global count
    for prefix, entries in rib.items():
        if not entries:
            continue

        entry = entries[0]                # FRR lists recursive NH first
        nhops = entry.get("nexthops", [])
        if not nhops:
            continue

        nh = None

        # --- INTERNAL NEXTHOP CHECK (same as original logic) ---
        for nhinfo in nhops:
            ip = nhinfo.get("ip")
            if not ip:
                continue

            ip = ip.split("/")[0]

            nh_node = ip_to_node.get(ip)
            if not nh_node:
                continue

            if int(nodes[nh_node]["asn"]) != asn:
                continue

            nh = ip
            break

        if not nh:
            continue

        seglist = f"{core_lo},{nh}"

        sh(
            f"ip -6 route replace {prefix} "
            f"encap seg6 mode encap segs {seglist} "
            f"dev {iface} table {table_id}"
        )

        count += 1

# ---- Install SRv6 for both tables ----
install_srv6_from_rib(rib0,   table_id=0,   core_lo=c2_lo, iface=d2)
install_srv6_from_rib(rib100, table_id=100, core_lo=c1_lo, iface=d1)

#this is changed in case of bgp removal
if not rib100:
    print(f"{me}: table 100 BGP RIB is empty, installing default-table routes into table 100 via core1")
    install_srv6_from_rib(rib0, table_id=100, core_lo=c1_lo, iface=d1)

print(f"{me}: installed SRv6 for {count} prefixes")

# ------------------------------------------------------------
# ECN rules → fwmark → table 100
# ------------------------------------------------------------
ecn_rules = [
    "-m ecn --ecn-tcp-ece -p tcp -j MARK --set-mark 100",
    "-m ecn --ecn-tcp-cwr -p tcp -j MARK --set-mark 100",
    "-m ecn --ecn-ip-ect 1 -j MARK --set-mark 100",
#    "-m ecn --ecn-ip-ect 2 -j MARK --set-mark 100",
    "-m ecn --ecn-ip-ect 3 -j MARK --set-mark 100",
    "-m ecn --ecn-ip-ect 1 -j DSCP --set-dscp 10",
    "-m ecn --ecn-ip-ect 3 -j DSCP --set-dscp 10",
]

for r in ecn_rules:
    if sh(f"ip6tables -t mangle -C PREROUTING {r}").returncode != 0:
        sh(f"ip6tables -t mangle -A PREROUTING {r}")

if "fwmark 0x64 lookup 100" not in sh("ip -6 rule show").stdout:
    sh("ip -6 rule add fwmark 100 table 100")

print(f"{me}: completed SRv6 policy application.")
