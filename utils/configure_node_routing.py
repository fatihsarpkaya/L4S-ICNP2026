#!/usr/bin/env python3
import argparse, json, os, subprocess, hashlib

# ----------------------------
# Small helpers
# ----------------------------
def parse_role_asn(n):
    if n.startswith("r-core1-"): return "core1", int(n.split("-")[-1])
    if n.startswith("r-core2-"): return "core2", int(n.split("-")[-1])
    if n.startswith("r-access-"): return "access", int(n.split("-")[-1])
    if n.startswith("e-"): return "endpoint", int(n.split("-")[-1])
    return "edge", int(n.split("-")[1])

ROLE_CODE = {"core1": 1, "core2": 2, "edge": 14, "access": 15, "endpoint": 254}

def edge_idx(n):
    p = n.split("-")
    if len(p) >= 3 and p[2].isdigit():
        return int(p[2])
    return int(hashlib.sha256(n.encode()).hexdigest()[:2], 16) % 253 + 2

def router_id(name, asn):
    role, _ = parse_role_asn(name)
    rc = ROLE_CODE[role]
    h = edge_idx(name) if role == "edge" else (asn or 1)
    return f"10.111.{rc}.{h}"

def neighbors_for(node, data):
    idx2name = [n.get("id") or n.get("name") for n in data["nodes"]]
    out = []
    for e in data["links"]:
        u = e["source"]; v = e["target"]
        u = idx2name[u] if isinstance(u, int) else u
        v = idx2name[v] if isinstance(v, int) else v
        if node in (u, v):
            ee = dict(e)
            ee["_u"], ee["_v"] = u, v
            out.append(ee)
    return out

# ----------------------------
# Parse arguments
# ----------------------------
ap = argparse.ArgumentParser()
ap.add_argument("--graph", required=True)
ap.add_argument("--ifmap", required=True)
ap.add_argument("--node", required=True)
ap.add_argument("--dry-run", action="store_true")
ap.add_argument("--restart-frr", action="store_true")
ap.add_argument("--config", required=False)
a = ap.parse_args()

topo = json.load(open(a.graph))
ifmap = json.load(open(a.ifmap))
node = a.node
role, asn = parse_role_asn(node)
nodes = {(n.get("id") or n.get("name")): n for n in topo["nodes"]}

# ----------------------------
# Load upgraded-AS info (optional)
# ----------------------------
as_upgraded = {}
if a.config:
    try:
        cfg = json.load(open(a.config))
        for rec in cfg.get("all_as", []):
            num = rec.get("number")
            if num is not None:
                as_upgraded[num] = bool(rec.get("upgraded", False))
    except Exception:
        as_upgraded = {}
is_upgraded = as_upgraded.get(asn, False)

# ----------------------------
# Build peer lists
# ----------------------------
peers = []      # eBGP only
int_ifs = set() # OSPF same-AS adjacencies

for e in neighbors_for(node, topo):
    u, v = e["_u"], e["_v"]
    fl = e.get("flavor")
    peer = v if u == node else u
    if fl in ("edge-edge", "edge-core", "access-core"):
        m = e.get("ip_map_v6") or {}
        if node in m and peer in m:
            p_ip = m[peer].split("/")[0]
            nic = ifmap[e.get("net_name") or e.get("lan")]
            if parse_role_asn(peer)[1] != asn:
                peers.append((p_ip, parse_role_asn(peer)[1], nic))
    if parse_role_asn(u)[1] == parse_role_asn(v)[1]:
        int_ifs.add(ifmap[e.get("net_name") or e.get("lan")])


# Track which intra-AS interfaces face core1 (for OSPF cost = 20)
core1_facing_ifs = set()
for e in neighbors_for(node, topo):
    u, v = e["_u"], e["_v"]
    peer = v if u == node else u
    if parse_role_asn(u)[1] == parse_role_asn(v)[1]:
        if parse_role_asn(peer)[0] == "core1":
            core1_facing_ifs.add(ifmap[e.get("net_name") or e.get("lan")])


# ----------------------------
# Full-mesh iBGP
# ----------------------------
ibgp_lo = []
for nname, nd in nodes.items():
    if nname != node and nname.startswith("r-"):
        r_role, r_asn = parse_role_asn(nname)
        if r_asn == asn:
            lo = nd.get("lo_v6")
            if lo:
                ibgp_lo.append(lo.split("/")[0])

# ----------------------------
# Access endpoint advertisements (CHANGED)
# ----------------------------
adv = []
if role == "access":
    for e in neighbors_for(node, topo):
        if e.get("flavor") == "edge-access":
            ip_map = e.get("ip_map_v6", {})
            for n, ip in ip_map.items():
                if n.startswith("e-"):
                    adv.append(f"{ip.split('/')[0]}/128")

# ----------------------------
# Build FRR config
# ----------------------------
rid = router_id(node, asn)
out = [
    "frr defaults traditional",
    f"hostname {node}",
    "service integrated-vtysh-config",
    "!",
    f"router bgp {asn}",
    f" bgp router-id {rid}",
    " no bgp ebgp-requires-policy"
]

for ip, rasn, nic in peers:
    out.append(f" neighbor {ip} remote-as {rasn}")
    out.append(f" neighbor {ip} update-source {nic}")

for ip in sorted(set(ibgp_lo)):
    out.append(f" neighbor {ip} remote-as {asn}")
    out.append(f" neighbor {ip} update-source lo")

out += ["!", " address-family ipv6 unicast"]

if role in ("access", "edge", "core1", "core2"):
    out.append("  maximum-paths 6")

for ip, rasn, nic in peers:
    out.append(f"  neighbor {ip} activate")
    out.append(f"  neighbor {ip} addpath-tx-all-paths")
    if role not in ("core1", "core2"):
        out.append(f"  neighbor {ip} route-map MATCH-ECN in")

for ip in sorted(set(ibgp_lo)):
    out.append(f"  neighbor {ip} activate")
    out.append(f"  neighbor {ip} addpath-tx-all-paths")
    if role not in ("core1", "core2"):
        out.append(f"  neighbor {ip} route-map MATCH-ECN in")
    out.append(f"  neighbor {ip} next-hop-self")

# ----------------------------
# Advertise prefixes (CHANGED)
# ----------------------------
ecn_used = False
for p in sorted(set(adv)):
    if role == "access" and is_upgraded and not ecn_used:
        out.append(f"  network {p} route-map ADD-ECN")
        ecn_used = True
    else:
        out.append(f"  network {p}")

out += [" exit-address-family", "!"]

# ----------------------------
# ECN route-map blocks
# ----------------------------
# if role == "access" and is_upgraded:
#     out += [
#         "!",
#         "bgp community-list standard ECN permit 65535:100",
#         "!",
#         "route-map MATCH-ECN permit 10",
#         " match community ECN",
#         " set table 100",
#         "route-map MATCH-ECN permit 20",
#         " match source-protocol bgp",
#         " set table 254",
#         "route-map ADD-ECN permit 10",
#         " set community 65535:100",
#         "exit",
#         "!",
#     ]

if role == "access" and is_upgraded:
    out += [
        "!",
        "bgp community-list standard ECN permit 65535:100",
        "bgp as-path access-list AS3-PATH permit _3_",
        "!",
        "route-map MATCH-ECN permit 10",
        " match community ECN",
        " set table 100",
        "route-map MATCH-ECN permit 20",
        " match as-path AS3-PATH",
        " set table 254",
        " set local-preference 150",
        "route-map MATCH-ECN permit 30",
        " match source-protocol bgp",
        " set table 254",
        "route-map ADD-ECN permit 10",
        " set community 65535:100",
        "exit",
        "!",
    ]

# if role == "edge" and is_upgraded and asn != 1:
#     out += [
#         "!",
#         "bgp community-list standard ECN permit 65535:100",
#         "!",
#         "route-map MATCH-ECN permit 10",
#         " match community ECN",
#         " set table 100",
#         " set local-preference 200",
#         "route-map MATCH-ECN permit 20",
#         " match source-protocol bgp",
#         " set table 254",
#         "exit",
#         "!",
#     ]

if role == "edge" and is_upgraded and asn != 1:
    out += [
        "!",
        "bgp community-list standard ECN permit 65535:100",
        "bgp as-path access-list AS3-PATH permit _3_",
        "!",
        "route-map MATCH-ECN permit 10",
        " match community ECN",
        " set table 100",
        " set local-preference 200",
        "route-map MATCH-ECN permit 20",
        " match as-path AS3-PATH",
        " set table 254",
        " set local-preference 150",
        "route-map MATCH-ECN permit 30",
        " match source-protocol bgp",
        " set table 254",
        "exit",
        "!",
    ]


elif role == "edge" and is_upgraded and asn == 1:
    # AS1 special case: only ECN-marked routes are accepted into BGP RIB
    # (no permit 20 → implicit deny on non-community routes). This forces
    # AS1 to advertise ONLY community-marked routes downstream, so AS5's
    # MATCH-ECN at the receiving end correctly classifies AS1-path into
    # table 100 and AS3-path into table 254. Verified with --restart-frr
    # on r-1-2: BGP RIB shrinks to community-only entries; table 254 BGP
    # routes go to 0; table 100 routes preserved.
    out += [
        "!",
        "bgp community-list standard ECN permit 65535:100",
        "!",
        "route-map MATCH-ECN permit 10",
        " match community ECN",
        " set table 100",
        " set local-preference 200",
        "exit",
        "!",
    ]

elif role == "edge" and not is_upgraded:
    out += [
        "!",
        "bgp community-list standard ECN permit 65535:100",
        "!",
        "route-map MATCH-ECN permit 10",
        " match community ECN",
        " set community none",
        "!",
        "route-map MATCH-ECN permit 20",
        " match source-protocol bgp",
        "!",
    ]

# ----------------------------
# OSPFv3
# ----------------------------
out += [
    "router ospf6",
    f" router-id {rid}",
    " debug ospf6 interface",
    " debug ospf6 neighbor",
    "!",
    "interface lo",
    " ipv6 ospf6 area 0.0.0.0",
    "exit",
    "!"
]

# for nic in sorted(int_ifs):
#     out += [
#         f"interface {nic}",
#         " ipv6 ospf6 area 0.0.0.0",
#         " ipv6 ospf6 network point-to-point",
#         "exit",
#         "!"
#     ]

for nic in sorted(int_ifs):
    block = [
        f"interface {nic}",
        " ipv6 ospf6 area 0.0.0.0",
        " ipv6 ospf6 network point-to-point",
    ]
    if nic in core1_facing_ifs:
        block.append(" ipv6 ospf6 cost 20")
    block += ["exit", "!"]
    out += block

out.append("!")

# ----------------------------
# Write FRR config
# ----------------------------
conf = "\n".join(out) + "\n"
os.makedirs("/etc/frr", exist_ok=True)
open("/etc/frr/frr.conf", "w").write(conf)
print("wrote /etc/frr/frr.conf")

# ----------------------------
# Enable daemons
# ----------------------------
d = "/etc/frr/daemons"
lines = []
for L in open(d):
    k = L.split("=")[0]
    if k in ("zebra", "bgpd", "ospf6d"):
        lines.append(f"{k}=yes")
    else:
        lines.append(L.strip())
open(d, "w").write("\n".join(lines) + "\n")

# ----------------------------
# Enable IPv6 + SRv6
# ----------------------------
if not a.dry_run:
    for s in ("all.forwarding=1", "all.seg6_enabled=1", "lo.seg6_enabled=1"):
        subprocess.run(["sysctl", "-w", "net.ipv6.conf." + s], check=False)
    for nic in ifmap.values():
        subprocess.run(
            ["sysctl", "-w", f"net.ipv6.conf.{nic}.seg6_enabled=1"],
            check=False
        )

    cmd = ["systemctl", "restart" if a.restart_frr else "start", "frr"]
    subprocess.run(cmd, check=False)
