# Extending Low Latency Service Across the Internet

This repository contains the artifacts for the paper **“Extending Low Latency Service Across the Internet,”** accepted for presentation at the **IEEE International Conference on Network Protocols (ICNP) 2026**.

## Abstract

Protocols such as L4S for low-latency network services have attracted growing interest from major industry stakeholders such as Comcast, Apple, T-Mobile, and NVIDIA. However, L4S requires isolation between L4S and non-L4S (“classic”) flows to maintain its low-latency benefits and safe coexistence. Although DualPI2 provides this isolation at the home access link, bottlenecks may also occur at peering points, wide-area network ingress, or congested core links where deploying DualPI2 is not feasible. We propose a practical deployment strategy using BGP communities, SRv6, and rate-capped priority queuing to extend low-latency service across independently managed networks without requiring upgrades to expensive core routers. We evaluate this strategy through large-scale experiments on the FABRIC testbed.

This repository includes:

- [`experiment_notebook.ipynb`](experiment_notebook.ipynb), the FABRIC experiment notebook.
- [`utils/`](utils/), containing the topology and routing configuration files used by the notebook.
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
