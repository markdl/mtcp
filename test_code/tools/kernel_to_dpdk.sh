#!/bin/bash

sudo ifconfig ens1 down
printf "13\n\n16\n\n20\n1024\n1024\n\n22\n0000:01:00.0\n\n33\n" | ~/mtcp/dpdk-16.11/tools/dpdk-setup.sh
sudo ip link set ens1 name dpdk0
sudo ~/mtcp/dpdk-16.11/tools/setup_iface_single_process.sh 128
ifconfig
