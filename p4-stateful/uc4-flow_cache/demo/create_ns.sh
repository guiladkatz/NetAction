#!/bin/bash

export DC_MAC="dc:dc:dc:dc:dc:dc"
export OTR_MAC="12:12:12:bb:bb:bb:bb"
export S1_MAC="12:12:12:11:11:11"
export S2_MAC="f2:f2:f2:f2:f2:f2"


#create 4 namespaces
ip netns a sswitch
ip netns a otr
ip netns a servers
ip netns a datacenter

#create veth interfaces
ip l a name otr_sswitch type veth peer name sswitch_otr
ip l a name servers_sswitch type veth peer name sswitch_servers
ip l a name dc_sswitch type veth peer name sswitch_dc

ip l set sswitch_otr netns sswitch
ip l set sswitch_servers netns sswitch
ip l set sswitch_dc netns sswitch

ip l set otr_sswitch netns otr
ip l set servers_sswitch netns servers
ip l set dc_sswitch netns datacenter

ip netns exec sswitch ip l set sswitch_otr up
ip netns exec sswitch ip l set sswitch_servers up
ip netns exec sswitch ip l set sswitch_dc up

ip netns exec otr ip l set otr_sswitch up
ip netns exec servers ip l set servers_sswitch up
ip netns exec datacenter ip l set dc_sswitch up

ip netns exec otr ifconfig otr_sswitch hw ether $OTR_MAC
ip netns exec datacenter ifconfig dc_sswitch hw ether $DC_MAC
ip netns exec servers ifconfig servers_sswitch hw ether $S1_MAC

ip netns exec otr ethtool -K otr_sswitch tx off
ip netns exec datacenter ethtool -K dc_sswitch tx off
ip netns exec servers ethtool -K servers_sswitch tx off
