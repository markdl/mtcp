#!/bin/bash

sudo ~/mtcp/dpdk-16.11/tools/dpdk-devbind.py -u 0000:01:00.0
sudo rmmod ixgbe
sudo modprobe ixgbe
sudo ifconfig ens1 inet 10.0.0.11
ifconfig
