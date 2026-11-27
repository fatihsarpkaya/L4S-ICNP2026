# Extending Low Latency Service Across the Internet

This repository contains the artifacts for the paper [**“Extending Low Latency Service Across the Internet,”**](https://ieeexplore.ieee.org/document/11783020) accepted for presentation at the **IEEE International Conference on Network Protocols (ICNP) 2026**.

## Abstract

Protocols such as L4S for low-latency network services have attracted growing interest from major industry stakeholders such as Comcast, Apple, T-Mobile, and NVIDIA. However, L4S requires isolation between L4S and non-L4S (“classic”) flows to maintain its low-latency benefits and safe coexistence. Although DualPI2 provides this isolation at the receiver access link, bottlenecks may also occur at peering points, wide-area network ingress, or congested core links, where deploying DualPI2 is not feasible. We propose a practical deployment strategy using BGP communities, SRv6, and rate-capped priority queuing to extend low-latency service across networks without requiring upgrades to all core routers on the path. We evaluate this strategy through large-scale experiments on the FABRIC testbed.

This repository includes:

- [`experiment_notebook.ipynb`](experiment_notebook.ipynb), the FABRIC experiment notebook.
- [`microbenchmark_notebook.ipynb`](microbenchmark_notebook.ipynb), the priority-queue saturation microbenchmark used for Figure 13.
- [`utils/`](utils/), containing the topology, routing, and SRv6 configuration files used by the notebook, including `ecn_copy_srv6.py`, which preserves CE marks across SRv6 decapsulation.
- [`Experiment_Data/`](Experiment_Data/), containing the main, motivation, and microbenchmark results.
- [`Plots/`](Plots/), containing the paper figures in PDF format.

## Reproducing the Figures

Use the provided experiment data to regenerate the paper figures with our Google Colab notebook:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1Ir2-Z9YPt8QX5052NF8G1l-1QfFy9InJ?usp=sharing)

You may also use your own experiment data by updating the data paths in the Colab notebook.

## Running the Experiments on FABRIC

You need a [FABRIC](https://fabric-testbed.net/) account, an active project with sufficient quota, configured SSH keys, and access to the FABRIC JupyterHub environment.

Open a terminal in FABRIC JupyterHub and run:

```bash
git clone https://github.com/fatihsarpkaya/L4S-ICNP2026.git
cd L4S-ICNP2026
cp utils/* .
```

Open `experiment_notebook.ipynb` in JupyterLab and follow its instructions section by section. Do not use **Run All**, because slice creation, node reboots, routing configuration, validation, and experiment execution must finish in order.

For the priority-queue saturation experiment in Figure 13, run `microbenchmark_notebook.ipynb` in the same way.

### Endpoint Software

Install `socat`, [MGEN](https://github.com/fatihsarpkaya/mgen), and [UDP Prague](https://github.com/fatihsarpkaya/udp_prague) on the experiment endpoint/helper nodes:

```bash
sudo apt update
sudo apt install -y socat build-essential g++ libpcap-dev git

mkdir -p ~/L4S_Project
cd ~/L4S_Project
git clone --recursive https://github.com/fatihsarpkaya/mgen.git
git clone https://github.com/fatihsarpkaya/udp_prague.git

cd ~/L4S_Project/udp_prague
make lib_prague
make udp_prague_receiver

cd ~/L4S_Project/mgen/makefiles
make -f Makefile.linux mgen
```

These commands create the paths expected by the notebook:

- `/home/ubuntu/L4S_Project/mgen/makefiles/mgen`
- `/home/ubuntu/L4S_Project/udp_prague/udp_prague_receiver`

The notebook provisions the topology, configures FRR/BGP/SRv6 and queue disciplines, runs the scenarios, and saves new measurements under `results/<scenario_id>/`. Delete the FABRIC slice after completing the experiments to release the reserved resources.


### ECN propagation at SRv6 decapsulation

Linux's SRv6 decapsulation removes the outer IPv6 header without copying its ECN field into the inner header, so a CE mark set by a queue inside an SRv6 segment would be lost. `utils/ecn_copy_srv6.py` compiles a small tc-eBPF program and attaches it at ingress on every edge and access router. For packets addressed to the router's own SID with Segments Left = 0, it copies an outer CE mark into the inner header before decapsulation, following RFC 6040 (outer CE over an inner Not-ECT packet is dropped). The notebook runs it right after the SRv6 setup cell; re-run that cell after any router reboot.

In the scenarios reported in the paper, the only queue inside an SRv6 segment that can CE-mark L4S packets is the L4S queue of the sender-access priority scheduler (S2b and S6c), and it recorded no ECN marks in any trial (`ecn_mark 0` in `tc_qdisc_r-access-5_trial*.txt`), so the published results do not depend on this step.
