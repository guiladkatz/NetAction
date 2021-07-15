#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_IPV4 0x0800
#define PROTO_TCP 0x6
#define PROTO_UDP 0X11

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

//Custom metadata definition
struct local_metadata_t {
    bit<8> ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<8> state;
    bool update_flow_ctx;
    bit<4> use_flow_key;
}

@metadata @name("flow_ctx_0")
struct flow_ctx_0_t {
    bit<32> state;
}

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;

        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

#define NEW 0
#define ESTABLISHED 1
#define LAN 0
#define WAN 1

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    table stage_0 {
        key = {
            hdr.ipv4.src_addr: exact; 
            hdr.ipv4.dst_addr: exact; 
            local_metadata.ip_proto: exact; 
            local_metadata.l4_src_port: exact; 
            local_metadata.l4_dst_port: exact; 
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

	apply {
        if (standard_metadata.ingress_port == LAN)
            local_metadata.use_flow_key = 0;
        else 
            local_metadata.use_flow_key = 1;

	    stage_0.apply();

        if (local_metadata.state == NEW && standard_metadata.ingress_port == LAN) {
            local_metadata.state = ESTABLISHED;
            standard_metadata.egress_spec = WAN;
        }
        else if (local_metadata.state == NEW && standard_metadata.ingress_port == WAN) {
            mark_to_drop();
        }
        else if (local_metadata.state == ESTABLISHED) {
            if (standard_metadata.ingress_port == LAN) {
                standard_metadata.egress_spec = WAN;
            }

            else if (standard_metadata.ingress_port == WAN) {
                standard_metadata.egress_spec = LAN;
            }
        }
        local_metadata.update_flow_ctx = true; 
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {}
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta) 
    { apply {} }

control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t meta) 
    { apply {} }

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
