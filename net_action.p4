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
    vxlan_ingress_downstream()  downstream1;
    vxlan_ingress_downstream()  downstream2;

    vxlan_ingress_upstream()    upstream;

    apply {
           if(standard_metadata.ingress_port == 1){
                downstream1.apply(hdr, meta, standard_metadata);
           } else {
                if(standard_metadata.ingress_port == 2){
                    downstream2.apply(hdr, meta, standard_metadata);
                }
                else {
                    upstream.apply(hdr, meta, standard_metadata); 
                }  
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
        if (standard_metadata.ingress_port == 1 || standard_metadata.ingress_port == 2) {
            downstream.apply(hdr, meta, standard_metadata);
        }
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