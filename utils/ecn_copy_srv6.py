#!/usr/bin/env python3
"""Install an SRv6 ECN/CE-copy TC ingress classifier on one FABRIC router.

Designed to be invoked exactly like srv6_policy.py:
  sudo python3 /tmp/ecn_copy_srv6.py \
      --graph /tmp/topology_node_link.json \
      --ifmap /tmp/ifmap-r-access-6.json \
      --node r-access-6

The C eBPF program is embedded below. No separate .c file is required in
Jupyter or in the repository. Runtime outputs are created under /tmp on the
remote router; the current BGP, SRv6, and root TC egress configurations are
not changed.

Assumptions: edge/access routers use their graph lo_v6 as their SRv6 decapsulation SID;
untagged Ethernet + outer IPv6 + SRH (no preceding extension headers) +
inner IPv6; the SRH is at its final segment (segments_left=0).
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

# Reserve one filter priority for this classifier; never flush other filters.
TC_PREF = "49152"
REMOTE_C = Path("/tmp/ecn_copy_srv6.c")
REMOTE_OBJ = Path("/tmp/ecn_copy_srv6.o")

# The installer replaces __LOCAL_SID_BYTES__ with this router's IPv6 SID.
BPF_C = r'''
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NEXTHDR_ROUTING 43
#define NEXTHDR_IPV6 41
#define SRH_ROUTING_TYPE 4
#define ECN_NOT_ECT 0
#define ECN_CE 3

SEC("classifier")
int ecn_copy_srv6(struct __sk_buff *skb)
{
    struct ethhdr eth = {};
    struct ipv6hdr outer = {}, inner = {};
    __u8 srh[8] = {};
    const __u8 local_sid[16] = __LOCAL_SID_BYTES__;

    // TC ingress sees the Ethernet header at offset zero.
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    if (eth.h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    const __u32 outer_off = sizeof(eth);
    if (bpf_skb_load_bytes(skb, outer_off, &outer, sizeof(outer)) < 0)
        return TC_ACT_OK;
    if (outer.version != 6 || outer.nexthdr != NEXTHDR_ROUTING)
        return TC_ACT_OK;

    // Act only on packets addressed to this router's own decap SID.
    const __u8 *dst = (const __u8 *)&outer.daddr;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (dst[i] != local_sid[i])
            return TC_ACT_OK;
    }

    const __u32 srh_off = outer_off + sizeof(outer);
    if (bpf_skb_load_bytes(skb, srh_off, srh, sizeof(srh)) < 0)
        return TC_ACT_OK;

    // SRH: byte 0 = next-header; 1 = hdr-ext-len (8-byte units minus 1);
    // 2 = routing type; 3 = segments-left.
    if (srh[0] != NEXTHDR_IPV6 ||
        srh[2] != SRH_ROUTING_TYPE ||
        srh[3] != 0)
        return TC_ACT_OK;

    const __u32 inner_off = srh_off + (((__u32)srh[1] + 1) * 8);
    if (inner_off + sizeof(inner) > skb->len)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, inner_off, &inner, sizeof(inner)) < 0)
        return TC_ACT_OK;
    if (inner.version != 6)
        return TC_ACT_OK;

    // IPv6 Traffic Class: ECN is in bits [5:4] of the second IPv6 byte.
    // Keep existing inner ECT(1)/ECT(0) and DSCP values unless CE arrived.
    const __u8 outer_b1 = ((__u8 *)&outer)[1];
    const __u8 inner_b1 = ((__u8 *)&inner)[1];
    const __u8 outer_ecn = (outer_b1 >> 4) & 3;
    const __u8 inner_ecn = (inner_b1 >> 4) & 3;

    if (outer_ecn != ECN_CE || inner_ecn == ECN_CE)
        return TC_ACT_OK;

    // Per RFC 6040: outer CE + inner Not-ECT is invalid at decap.
    if (inner_ecn == ECN_NOT_ECT)
        return TC_ACT_SHOT;

    // Write only ECN bits; preserve inner DSCP and flow label bits.
    const __u8 modified_b1 = (inner_b1 & 0xCF) | (ECN_CE << 4);
    if (bpf_skb_store_bytes(skb, inner_off + 1,
                            &modified_b1, 1, BPF_F_RECOMPUTE_CSUM) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
'''


def command(argv, *, capture=True):
    """Run a command, raising a useful error on nonzero exit."""
    result = subprocess.run(argv, text=True, capture_output=capture)
    if result.returncode:
        detail = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
        raise RuntimeError(f"{' '.join(map(str, argv))}\n{detail}")
    return result.stdout or ""


def install_build_dependencies():
    """Only install compiler packages when not already present."""
    if Path("/usr/include/bpf/bpf_helpers.h").is_file() and (
        Path("/usr/bin/clang").exists() or shutil.which("clang")
    ):
        return
    print("  Installing clang and libbpf-dev (if necessary)...", flush=True)
    command(["apt-get", "update", "-qq"])
    command(["apt-get", "install", "-y", "-qq", "clang", "llvm", "libbpf-dev"])


def compile_program():
    """Prefer distribution clang with the BPF backend over unrelated clangs."""
    include_dir = Path("/usr/include") / (platform.machine() + "-linux-gnu")
    candidates = [Path(f"/usr/bin/clang-{v}") for v in (20, 19, 18, 17, 16, 15, 14, 13)]
    candidates += [Path("/usr/bin/clang")]
    path_clang = shutil.which("clang")
    if path_clang:
        candidates.append(Path(path_clang))
    tried = set()
    errors = []
    for compiler in candidates:
        if str(compiler) in tried or not compiler.exists():
            continue
        tried.add(str(compiler))
        argv = [str(compiler), "-O2", "-target", "bpf"]
        if include_dir.is_dir():
            argv += ["-I", str(include_dir)]
        argv += ["-c", str(REMOTE_C), "-o", str(REMOTE_OBJ)]
        result = subprocess.run(argv, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  Compiled using {compiler}", flush=True)
            return
        errors.append(f"{compiler}: {(result.stderr or result.stdout).strip()[:700]}")
    raise RuntimeError("Could not compile eBPF program:\n" + "\n".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--ifmap", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    topology = json.loads(Path(args.graph).read_text())
    nodes = {n["id"]: n for n in topology["nodes"]}
    if args.node not in nodes:
        parser.error(f"Node not found in graph: {args.node}")

    node_info = nodes[args.node]
    role = node_info["role"].lower()
    if role not in ("edge", "access"):
        print(f"[SKIP] {args.node}: role={role} (no End.DT6 expected)")
        return 0

    # Same per-node net_name -> Linux interface mapping used by srv6_policy.py.
    ifmap = json.loads(Path(args.ifmap).read_text())
    if not isinstance(ifmap, dict):
        raise RuntimeError(f"Expected network -> interface map in {args.ifmap}")
    devices = sorted({dev for dev in ifmap.values()
                      if isinstance(dev, str) and dev and dev != "lo"})
    if not devices:
        raise RuntimeError(f"No data interfaces in interface map for {args.node}")

    sid = ipaddress.IPv6Address(node_info["lo_v6"].split("/")[0])
    sid_literal = "{" + ", ".join(f"0x{byte:02x}" for byte in sid.packed) + "}"
    src = BPF_C.replace("__LOCAL_SID_BYTES__", sid_literal)

    print(f"[{args.node}] role={role} local SID={sid}")
    print(f"[{args.node}] TC ingress interfaces: {', '.join(devices)}", flush=True)
    if args.dry_run:
        print("[DRY RUN] No files, packages, qdiscs, or filters were changed.")
        return 0

    if os.geteuid() != 0:
        raise RuntimeError("Run as root: sudo python3 ecn_copy_srv6.py ...")


    # Fail before attachment if an interface map is stale.
    for dev in devices:
        if not (Path("/sys/class/net") / dev).exists():
            raise RuntimeError(f"Mapped interface {dev} does not exist on {args.node}")

    REMOTE_C.write_text(src)
    install_build_dependencies()
    compile_program()

    for dev in devices:
        qdisc = command(["tc", "qdisc", "show", "dev", dev])
        if not re.search(r"\bqdisc\s+(clsact|ingress)\b", qdisc):
            # clsact is independent of the existing root/equipment qdisc.
            command(["tc", "qdisc", "add", "dev", dev, "clsact"])

        old = command(["tc", "filter", "show", "dev", dev,
                       "ingress", "pref", TC_PREF])
        if old.strip() and "ecn_copy_srv6" not in old:
            raise RuntimeError(
                f"Refusing to replace an unrelated ingress filter on {dev} "
                f"at priority {TC_PREF}:\n{old}"
            )

        command(["tc", "filter", "replace", "dev", dev, "ingress",
                 "protocol", "ipv6", "pref", TC_PREF, "handle", "1", "bpf", "da",
                 "obj", str(REMOTE_OBJ), "sec", "classifier"])
        print(f"  [ATTACHED] {dev}", flush=True)

    print(f"ECN_COPY_DONE {args.node} {len(devices)}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
