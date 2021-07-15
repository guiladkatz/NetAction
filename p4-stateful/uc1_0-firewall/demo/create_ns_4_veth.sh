#!/bin/bash

ip netns a switch
ip netns a lan
ip netns a wan

ip l a name veth0 type veth peer name veth1
ip l a name veth2 type veth peer name veth3

ip l set veth1 netns switch
ip l set veth2 netns switch

ip l set veth0 netns lan
ip l set veth3 netns wan

ip netns exec switch ip l set veth1 up
ip netns exec switch ip l set veth2 up

ip netns exec lan ip l set veth0 up
ip netns exec wan ip l set veth3 up

ip netns exec lan ifconfig veth0 hw ether 12:12:12:11:11:11
ip netns exec wan ifconfig veth3 hw ether 12:12:12:22:22:22

ip netns exec lan ip a a 10.0.0.1/24 dev veth0
ip netns exec wan ip a a 160.80.10.1/32 dev veth3

ip netns exec lan ip r a 160.80.10.1/32 dev veth0

ip netns exec lan arp -s 160.80.10.1 12:12:12:22:22:22
ip netns exec wan arp -s 10.0.0.1 12:12:12:11:11:11

ip netns exec lan ethtool -K veth0 tx off
ip netns exec wan ethtool -K veth3 tx off
ip netns exec lan ip l set lo up
ip netns exec wan ip l set lo up

ip netns exec switch bash
