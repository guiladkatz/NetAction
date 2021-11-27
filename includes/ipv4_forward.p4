#ifndef __IPV4_FORWARD__
#define __IPV4_FORWARD__

#include "headers.p4"


#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define VXLAN_HDR_SIZE 8
#define IP_VERSION_4 4
#define IPV4_MIN_IHL 5
#define TEMP_PORT 10
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

    table t_vxlan_term { // A match on this table means that the destination MAC address of the original packet is connected to this switch
                        //  In this case, decapsulate the headers of the packet.
        key = {
            // Inner Ethernet desintation MAC address of target host
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

    table t_forward_underlay { // If there is a match on an IP in this table, then the packet should leave through the port specified by the forward_underlay action.
        key = {
            hdr.ipv4.dstAddr : exact;
        }

        actions = {
            forward_underlay;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(!t_forward_underlay.apply().hit){// If miss, then the incoming packet can only be going to me, so decap and forward localy
                                                // If hit, then the packet came from some other switch (Or the controller) and should not be decapsulated, only forwarded
                if (t_vxlan_term.apply().hit) { // Checks if the destination host is connected to this switch
                    t_forward_l2.apply();       // Checks if the destination host is connected to this switch, and assign the correct egress port
                                                // Probably, these two tables can be merged into one (move the egress port assignment to the vxlan_decap action)
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
    //counter(MAX_PORTS_NUM,CounterType.packets) flow_counter;

    action set_vni(bit<24> vni) {
        meta.vxlan_vni = vni; //Sets the vni of the packet according to the vni value inserted to the t_vxlan_segment table by the Control Plane.
    }
    // The following action doesn't have a practical use. If there is a miss in the cache, we want the packet to be forwarded to the controller ALWAYS.
    // But the IP and port of the controller can change between switches, so we want to be able to insert these values form Control Plane.
    // In order to do that, we need to use a table. This table is the t_controller table. But we need to match against some value,
    // so I used the set_temp_egress_spec action to set the standard_metadata.egress_spec to a constant temporary value, that can be always matched in the t_controller table.
    // So, in case a packet missed the cache, the default action will be called which is set_temp_egress_spec.
    // Contact me for more details.
    action set_temp_egress_spec() {
        standard_metadata.egress_spec = TEMP_PORT; // Sets the egress port of the packet to be the port where the controller is located.
    }

    action set_outer_dst_ip(bit<32> dst_ip,bit<9> port) {
        // If there is a match in the Cache, assign the egress port and destination IP of the outter IP header of the packet.
        standard_metadata.egress_spec = port;
        meta.dst_ip = dst_ip;
        my_direct_counter.count(); // Direct Counter to count number of packets that matched this rule. You can put it at any action you desire.
    }
    action drop() {
        // Drop the packet
        mark_to_drop(standard_metadata);
    }

    table t_vxlan_segment { // From the Control Plane, assign to every host connected to a switch port a different vni. The set_vni action will assign the vni to the VXLAN packet header at the egress stage.
        key = {
            standard_metadata.ingress_port : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_vni;
        }
    }

    table flow_cache { // This is the Cache. match against destination IP address of the inner IPv4 header, and if there is a hit call the set_outer_dst_ip action.
        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            set_outer_dst_ip;
            set_temp_egress_spec
            drop;
        }
        default_action = set_temp_egress_spec; // The default action will be called upon a cache miss. Since we cannot insert values from the Control Plane to a default action, we need the t_controller table.
        counters = my_direct_counter; // Tell the table that a Direct Counter called my_direct_counter is attached to each entry of the table.

    }

    action set_vtep_ip(bit<32> vtep_ip) {
        meta.vtepIP = vtep_ip; // Set the IP of the Vtep. This will be assigned to the source IP of the outter IPv4 header at the egress stage.
    }

    table t_vtep { // A table to match against the ethernet source address, and call the set_vtep_ip if there is a match.
        key = {
            hdr.ethernet.srcAddr : exact;
        }

        actions = {
            set_vtep_ip;
        }

    }
    // Sets the IP of the controller. It will later be assigned to the destination IP address of the outter IPv4 header.
    // Set also the port where the packet should leave from in order to reach the controller (may be different at every switch)
    action set_controller_ip_and_port(bit<32> dst_ip,bit<9> port) {
        meta.dst_ip = dst_ip;
        standard_metadata.egress_spec = port;
    }

    // Action to deal with ARP packets. This should be modified according to the address in your topology. If static ARP entries were inserted to the tables at the hosts, this action won't be called.
    action set_arp() {
        hdr.arp.oper = 2;
        hdr.arp.dstMacAddr = hdr.arp.srcMacAddr;  //Because in my topology, the switch and the host interfaces have the same mac
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        standard_metadata.egress_spec = 1;
        bit<32> tmp_ip = hdr.arp.srcIPAddr;
        hdr.arp.srcIPAddr = hdr.arp.dstIPAddr;
        hdr.arp.dstIPAddr = tmp_ip;
    }

    // If there is a miss, this table will be applyed. The match variable (standard_metadata.egress_spec) doesn't have a lot of meaning here. The action that is called is more important.
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
            t_vtep.apply(); //Assign Vtep IP address (in the egress stage will be assigned to the IP source address in the outter IP header)
            t_vxlan_segment.apply(); //Match against the ingress port, and assign the vni accordingly
            if(!flow_cache.apply().hit) { //If there is a hit in the cache to the inner header destination IP address of the packet, set the destination IP of the outter header to the destination switch
                t_controller.apply();     //If there is a miss in the cache, send the packet to the controller 
            }
        } else {
            if(hdr.arp.isValid()){ //If the packet is not IPv4, but ARP, call the set_arp() action. This function assumes static ARP entries were NOT given to the hosts.
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
        // This action plugs the values that were received in the ingress downstream stage into their relevant place in the headers.
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
        hdr.vxlan.reserved_2 = 0;
        hdr.vxlan.flags = 0;
        hdr.vxlan.vni = meta.vxlan_vni;

    }

    apply {
        if (meta.dst_ip != 0) { // This if statement was inserted to cover the case where the packet shouldn't be encapsulated (e.g., If the packet goes to another host connected to this switch)
                                // In the Control Plane, the value 0 was inserted to the set_controller_ip_and_port action to indicate this case.
            vxlan_encap();      // call the VXLAN Encapsulation action.
            t_send_frame.apply(); // A table to properly adjust the MAC addresses.
        }
    }
}

#endif