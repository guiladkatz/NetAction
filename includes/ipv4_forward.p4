#ifndef __IPV4_FORWARD__
#define __IPV4_FORWARD__

#include "headers.p4"


#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define VXLAN_HDR_SIZE 8
#define IP_VERSION_4 4
#define IPV4_MIN_IHL 5
#define CONTROLLER_PORT 3
#define SWITCH_TO_SWITCH_PORT 4

const bit<32> MAX_PORTS_NUM = 1 << 16;
const bit<32> MAX_RANDOM_RULES = 1 << 4;


control vxlan_ingress_upstream(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    action vxlan_decap() {
        // as simple as set outer headers as invalid
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.vxlan.setInvalid();
    }

    table t_vxlan_term {
        key = {
            // Inner Ethernet desintation MAC address of target VM
            hdr.inner_ethernet.dstAddr : exact;
        }

        actions = {
            @defaultonly NoAction;
            vxlan_decap();
        }

    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table t_forward_l2 {
        key = {
            hdr.inner_ethernet.dstAddr : exact;
        }

        actions = {
            forward;
        }
    }

    action forward_underlay(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table t_forward_underlay {
        key = {
            hdr.ipv4.dstAddr : exact;
        }

        actions = {
            forward_underlay;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(!t_forward_underlay.apply().hit){//If miss, then the incoming packet can only be going to me, so decap and forward localy
                if (t_vxlan_term.apply().hit) {
                    t_forward_l2.apply();
                }
            }
        }
    }
}

control vxlan_egress_upstream(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    apply {

    }

}

control vxlan_ingress_downstream(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets) my_direct_counter;
    counter(1,CounterType.packets) flow_counter;
    counter(1,CounterType.packets) entry_flow_counter;


    action set_vni(bit<24> vni) {
        meta.vxlan_vni = vni;
    }
    action send_to_controller() {
        flow_counter.count(0);
        standard_metadata.egress_spec = CONTROLLER_PORT;
    }

    action set_outer_dst_ip(bit<32> dst_ip,bit<9> port) {
        standard_metadata.egress_spec = port;
        meta.dst_ip = dst_ip;
        //flow_counter.count(hdr.ipv4.dstAddr & 0x0000ffff);
        //flow_counter.count(0);
        //my_direct_counter.count();

    }
    action drop() {
        my_direct_counter.count();
        mark_to_drop(standard_metadata);
    }

    table lfu {

        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            @defaultonly NoAction;
            drop;
        }
    }

    table t_vxlan_segment {

        key = {
            standard_metadata.ingress_port : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_vni;
        }
    }

    table flow_cache {
        support_timeout = true;
        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            set_outer_dst_ip;
            send_to_controller;
            drop;
        }
        default_action = send_to_controller();
        counters = my_direct_counter;
    }

    action set_vtep_ip(bit<32> vtep_ip) {
        meta.vtepIP = vtep_ip;
    }

    table t_vtep {
        key = {
            hdr.ethernet.srcAddr : exact;
        }

        actions = {
            set_vtep_ip;
        }

    }

    action set_controller_ip_and_port(bit<32> dst_ip,bit<9> port) {
        meta.dst_ip = dst_ip;
        standard_metadata.egress_spec = port;
    }

    action set_arp() {
        hdr.arp.oper = 2;
        hdr.arp.dstMacAddr = hdr.arp.srcMacAddr;  //Because in my topology, the switch and the host interfaces have the same mac
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        standard_metadata.egress_spec = 1;
        bit<32> tmp_ip = hdr.arp.srcIPAddr;
        hdr.arp.srcIPAddr = hdr.arp.dstIPAddr;
        hdr.arp.dstIPAddr = tmp_ip;
    }

    table t_controller {

        key = {
            standard_metadata.egress_spec : exact;
        }

        actions = {
            set_controller_ip_and_port;
        }
    }
    apply {
        if (hdr.ipv4.isValid()) {
            entry_flow_counter.count(0);
            lfu.apply();
            t_vtep.apply();
            t_vxlan_segment.apply();
            if(!flow_cache.apply().hit) {                
                t_controller.apply();       
            }
        } else {
            if(hdr.arp.isValid()){
                //t_arp.apply();
                set_arp();
            }
        }
    }
}

control vxlan_egress_downstream(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    action rewrite_macs(bit<48> smac, bit<48> dmac) {
        hdr.ethernet.srcAddr = smac;
        hdr.ethernet.dstAddr = dmac;
    }

    table t_send_frame {

            key = {
                hdr.ipv4.dstAddr : exact;
            }

            actions = {
                rewrite_macs;
            }
        }

    action vxlan_encap() {

        hdr.inner_ethernet = hdr.ethernet;
        hdr.inner_ipv4 = hdr.ipv4;

        hdr.ethernet.setValid();

        hdr.ipv4.setValid();
        hdr.ipv4.version = IP_VERSION_4;
        hdr.ipv4.ihl = IPV4_MIN_IHL;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen
                            + (ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.ipv4.identification = 0x1513; /* From NGIC */
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = UDP_PROTO;
        hdr.ipv4.dstAddr = meta.dst_ip;
        hdr.ipv4.srcAddr = meta.vtepIP;
        hdr.ipv4.hdrChecksum = 0;

        hdr.udp.setValid();
        // The VTEP calculates the source port by performing the hash of the inner Ethernet frame's header.
        hash(hdr.udp.srcPort, HashAlgorithm.crc16, (bit<13>)0, { hdr.inner_ethernet }, (bit<32>)65536);
        hdr.udp.dstPort = UDP_PORT_VXLAN;
        hdr.udp.length = hdr.ipv4.totalLen + (UDP_HDR_SIZE + VXLAN_HDR_SIZE);
        hdr.udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.reserved = 0;
        hdr.vxlan.next_proto = 0x3;
        hdr.vxlan.reserved_2 = 0;
        hdr.vxlan.flags = 0xc;
        hdr.vxlan.vni = meta.vxlan_vni;

    }

    apply {
        if (meta.dst_ip != 0) {
            vxlan_encap();
            t_send_frame.apply();
        }
    }

}

#endif