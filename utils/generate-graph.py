# Build a full NetworkX topology (edge-edge, edge-core, access-core uplinks, access LANs) from the single generator JSON.
# Exports topology_node_link.json (node-link format with attributes).

import json, ipaddress, hashlib, argparse, networkx as nx
from networkx.readwrite import json_graph

# ---------- helpers ----------
def load_gen_config(path: str):
    """Load the one-file generator output and return (net_conf, core_net_conf, access_net_conf, access_border_net_conf)."""
    with open(path) as f:
        cfg = json.load(f)
    for key in ("net_conf", "core_net_conf", "access_net_conf", "access_border_net_conf"):
        if key not in cfg or not isinstance(cfg[key], list):
            raise ValueError(f"Config must contain list '{key}'")
    return cfg["net_conf"], cfg["core_net_conf"], cfg["access_net_conf"], cfg["access_border_net_conf"]

def parse_role_asn(name: str):
    """
    Returns (role, asn) for known device name patterns from your generator.
    """
    if name.startswith("r-core1-"):
        return "core1", int(name.split("-")[-1])
    if name.startswith("r-core2-"):
        return "core2", int(name.split("-")[-1])
    if name.startswith("r-access-"):
        return "access", int(name.split("-")[-1])
    if name.startswith("e-"):
        parts = name.split("-")  # e-<i>-<asn>
        return "endpoint", int(parts[-1])
    return "edge", int(name.split("-")[1])

def _edge_idx_from_name(name: str) -> int:
    try:
        parts = name.split("-")
        if len(parts) >= 3 and parts[2].isdigit():
            return int(parts[2])
    except Exception:
        pass
    h = int(hashlib.sha256(name.encode()).hexdigest()[:2], 16)
    return max(1, (h % 15))

# ---------- FIX ADDED ----------
def endpoint_idx_from_name(name: str) -> int:
    # e-<i>-<asn>
    try:
        parts = name.split("-")
        if len(parts) >= 3 and parts[1].isdigit():
            return int(parts[1])
    except Exception:
        pass
    return 1
# --------------------------------

def lo_for(role: str, asn: int, name: str) -> str:
    """
    Loopbacks under fd00:ffff::/32
    """
    if asn < 0 or asn > 0xFFFF:
        asn_hex = int(hashlib.sha256(str(asn).encode()).hexdigest()[:4], 16)
    else:
        asn_hex = asn

    r = role.lower()
    if r == "core1":
        return f"fd00:ffff:1:{asn_hex}::1"
    if r == "core2":
        return f"fd00:ffff:2:{asn_hex}::1"
    if r == "edge":
        idx = _edge_idx_from_name(name)
        return f"fd00:ffff:14:{asn_hex}::{idx}"
    if r == "access":
        return f"fd00:ffff:f:{asn_hex}::1"

    # ---------- FIX HERE ----------
    if r == "endpoint":
        idx = endpoint_idx_from_name(name)
        return f"fd00:ffff:fe:{asn_hex}::{idx}"
    # --------------------------------

    return f"fd00:ffff:ff:{asn_hex}::1"

def v6_prefix_from_v4_subnet(v4_subnet: str) -> ipaddress.IPv6Network:
    parts = v4_subnet.split(".")
    if len(parts) < 4:
        raise ValueError(f"Bad IPv4 subnet: {v4_subnet}")
    x, y = int(parts[1]), int(parts[2])
    return ipaddress.IPv6Network(f"fd00:{x}:{y}::/64")

def add_node_if_absent(G: nx.Graph, name: str):
    if name not in G:
        role, asn = parse_role_asn(name)
        G.add_node(name, role=role, asn=asn)
        G.nodes[name]["lo_v6"] = lo_for(role, asn, name)
    else:
        n = G.nodes[name]
        if "lo_v6" not in n or not n["lo_v6"]:
            n["lo_v6"] = lo_for(n.get("role","edge"), int(n.get("asn",0)), name)

# ---------- builder ----------
def build_graph_from_config(config_path: str) -> nx.Graph:
    net_conf, core_conf, access_conf, access_uplink_conf = load_gen_config(config_path)
    G = nx.Graph()

    # --- edge-edge links ---
    for entry in net_conf:
        nodes = entry["nodes"]
        n1, n2 = nodes[0]["name"], nodes[1]["name"]
        add_node_if_absent(G, n1)
        add_node_if_absent(G, n2)

        v6 = v6_prefix_from_v4_subnet(entry["subnet"])
        asn1, asn2 = G.nodes[n1]["asn"], G.nodes[n2]["asn"]
        host_map = {n1: (1 if asn1 <= asn2 else 2),
                    n2: (1 if asn2 <  asn1 else 2)}

        def v6_ip_for(node: str) -> str:
            return str(ipaddress.IPv6Address(int(v6.network_address) + host_map[node]))

        G.add_edge(
            n1, n2,
            flavor="edge-edge",
            v4_subnet=entry["subnet"],
            v6_prefix=str(v6),
            ip_map_v6={n1: v6_ip_for(n1), n2: v6_ip_for(n2)},
            net_name=entry["name"],
        )

    # --- edge-core fanout links ---
    for entry in core_conf:
        nodes = entry["nodes"]
        n1, n2 = nodes[0]["name"], nodes[1]["name"]
        add_node_if_absent(G, n1)
        add_node_if_absent(G, n2)

        v6 = v6_prefix_from_v4_subnet(entry["subnet"])
        role1, role2 = G.nodes[n1]["role"], G.nodes[n2]["role"]

        if role1.startswith("core") and not role2.startswith("core"):
            edge_node, core_node = n2, n1
        elif role2.startswith("core") and not role1.startswith("core"):
            edge_node, core_node = n1, n2
        else:
            edge_node, core_node = (n1, n2)

        host_map = {edge_node: 1, core_node: 2}

        def v6_ip_for(node: str) -> str:
            return str(ipaddress.IPv6Address(int(v6.network_address) + host_map[node]))

        G.add_edge(
            n1, n2,
            flavor="edge-core",
            v4_subnet=entry["subnet"],
            v6_prefix=str(v6),
            ip_map_v6={n1: v6_ip_for(n1), n2: v6_ip_for(n2)},
            net_name=entry["name"],
        )

    # --- access-core uplinks ---
    for entry in access_uplink_conf:
        nodes = entry["nodes"]
        n1, n2 = nodes[0]["name"], nodes[1]["name"]
        add_node_if_absent(G, n1)
        add_node_if_absent(G, n2)

        v6 = v6_prefix_from_v4_subnet(entry["subnet"])
        role1, role2 = G.nodes[n1]["role"], G.nodes[n2]["role"]

        if role1 == "access":
            access_node, core_node = n1, n2
        else:
            access_node, core_node = n2, n1

        host_map = {access_node: 1, core_node: 2}

        def v6_ip_for(node: str) -> str:
            return str(ipaddress.IPv6Address(int(v6.network_address) + host_map[node]))

        G.add_edge(
            n1, n2,
            flavor="access-core",
            v4_subnet=entry["subnet"],
            v6_prefix=str(v6),
            ip_map_v6={n1: v6_ip_for(n1), n2: v6_ip_for(n2)},
            net_name=entry["name"],
        )

    # --- access LANs ---
    for access in access_conf:
        subnet_v4 = access["subnet"]
        name = access["name"]
        nodes = access["nodes"]
        v6 = v6_prefix_from_v4_subnet(subnet_v4)

        gw = next(n["name"] for n in nodes if n["name"].startswith("r-access-"))
        add_node_if_absent(G, gw)

        v6_addr = {}
        for n in nodes:
            add_node_if_absent(G, n["name"])
            role = G.nodes[n["name"]]["role"]
            if role == "access":
                host = 1
            else:
                last_octet = int(n["addr"].split(".")[-1])
                host = 2 if last_octet == 1 else last_octet
            v6_addr[n["name"]] = str(ipaddress.IPv6Address(int(v6.network_address) + host))

        for n in nodes:
            if n["name"] == gw:
                continue
            G.add_edge(
                gw, n["name"],
                flavor="edge-access",
                v4_subnet=subnet_v4,
                v6_prefix=str(v6),
                ip_map_v6={gw: v6_addr[gw], n["name"]: v6_addr[n["name"]]},
                lan=name,
            )

    return G

ap = argparse.ArgumentParser()
ap.add_argument("--i", default="fabric_small_config.json")
ap.add_argument("--o", default="topology_node_link.json")
a = ap.parse_args()

G = build_graph_from_config(a.i)
data = json_graph.node_link_data(G)

with open(a.o, "w") as f:
    json.dump(data, f, indent=2)

print(f"Wrote {a.o} with {G.number_of_nodes()} nodes and {G.number_of_edges()} links")
