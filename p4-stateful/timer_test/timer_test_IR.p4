#include <core.p4>
#include <v1model.p4>

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
    bit<64> ticks_now;
    bit<8> state;
    bit<64> timeout;
    bool send;
    bool update_flow_ctx;
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
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;

        transition select(hdr.ipv4.protocol) {
            0x6: parse_tcp;
            0x11: parse_udp;
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

#define TIMEOUT_1 1000
#define TIMEOUT_2 2000

#define NEW 0
#define ALTERNATE 1
#define DROP 2

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
        stage_0.apply();

        //if (timer.ticks_now == flow_ctx.timeout) {
        if (standard_metadata.ingress_port == 200) {
            if (local_metadata.ticks_now >= local_metadata.timeout) {
                if (local_metadata.state == NEW) { } 
                else if (local_metadata.state == ALTERNATE) {
                    // this timer will fire in drop state
                    local_metadata.timeout = local_metadata.ticks_now + TIMEOUT_1;

                    //transition drop;
                    local_metadata.state = DROP;
                } else if (local_metadata.state == DROP) {
                    // this timer will fire in alternate state
                    local_metadata.timeout = local_metadata.ticks_now + TIMEOUT_2;

                    //transition alternate;
                    local_metadata.state = ALTERNATE;
                }  
                local_metadata.update_flow_ctx = true; 
            }
        } else {
            if (local_metadata.state == NEW) {
                local_metadata.timeout = local_metadata.ticks_now + 1000; // timeout in ticks

                local_metadata.send = true;
                //transition alternate;
                local_metadata.state = ALTERNATE;
            } else if (local_metadata.state == ALTERNATE) {
                if (local_metadata.send) {
                    standard_metadata.egress_spec = 1;
                    local_metadata.send = false;
                } else {
                    mark_to_drop();
                    local_metadata.send = true;
                }
            } else if (local_metadata.state == DROP) {
                mark_to_drop();
            }  
            local_metadata.update_flow_ctx = true; 
        } 
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
