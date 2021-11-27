/*
    Basic P4 switch program for tutor. (with simple functional support)
*/
#include <core.p4>
#include <v1model.p4>

#include "includes/headers.p4"
#include "includes/checksums.p4"
#include "includes/parser.p4"

// application
#include "includes/ipv4_forward.p4"
//#include "includes/packetio.p4"



//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------
control basic_tutorial_ingress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
){
    // Each host connected to the switch has a seperate control block, and thus a seperate pipeline.
    // The reason is that I couldnt find a better way to seperate them, if they both try to send a packet to the same destination host.
    // For more detailed explanation please contact me. 
    // In your case, you have only one host connected to each switch, so you need only one downstream control block.

    vxlan_ingress_downstream()  downstream; // Describes flow of packets coming from "down" (i.e., The hosts)
    vxlan_ingress_upstream()    upstream; // // Describes flow of packets coming from "up" (i.e., Other switches in the network, the controller, etc)

    // If the packet came from port 1 or port 3 (which is the port connected to the host 1 in switch 1 and host 3 in switch 3, respectively)
    // Be aware the number in your case may differ!!
    // The thumb rule is: Only packets coming from ports connected to hosts should go to downlink processing
    // Packets coming from other switches or the controller, should go to upstream processing
    apply {
           if(standard_metadata.ingress_port == 1 || standard_metadata.ingress_port == 3) 
           {
                downstream.apply(hdr, meta, standard_metadata);
           } 
           else 
           {
                upstream.apply(hdr, meta, standard_metadata); 
           }
    }  
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------
control basic_tutorial_egress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
){
    vxlan_egress_downstream()  downstream;

    apply {
        if (standard_metadata.ingress_port == 1) { //if the packet came from port 1 (which is the port connected to the host, be aware the number in your case may differ)
            downstream.apply(hdr, meta, standard_metadata); 
        }
        // no 'else', since if the packet came from anywhere else, uplink egress processing is not needed.
    }
}

//------------------------------------------------------------------------------
// SWITCH ARCHITECTURE
//------------------------------------------------------------------------------
V1Switch(
    basic_tutor_switch_parser(),
    basic_tutor_verifyCk(),
    basic_tutorial_ingress(),
    basic_tutorial_egress(),
    basic_tutor_computeCk(),
    basic_tutor_switch_deparser()
) main;