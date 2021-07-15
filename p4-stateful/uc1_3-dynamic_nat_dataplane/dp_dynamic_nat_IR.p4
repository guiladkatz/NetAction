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
    bit<16> tcp_length;
    bit<64> ticks_now;
    bit<8> state_0;
    bit<16> nat_port;
    bit<64> timeout;
    bool update_flow_ctx0;
    bool update_flow_ctx1;
    bit<4> use_flow_key0;
    bit<4> use_flow_key1;
    bit<16> stage1_fk;
    bit<8> state_1;
    bit<32> internal_ip_addr; 
    bit<16> internal_port;
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
        local_metadata.tcp_length = hdr.ipv4.total_len - 16w20;

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
#define FREE_PORT_PICKED_UP 1
#define ESTABLISHED 1

#define CONNECTION_TIMEOUT 10

#define INTERNAL 0
#define EXTERNAL 1

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) natIPAddress;
    register<bit<16>>(65535) ports;

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

    table stage_1 {
        key = {
            local_metadata.stage1_fk: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (standard_metadata.ingress_port == INTERNAL)
            local_metadata.use_flow_key0 = 0;
        else 
            local_metadata.use_flow_key0 = 1;

        stage_0.apply();        

        // ######### Stage 0 timer graph
        if (standard_metadata.ingress_port == 200) {
            if (local_metadata.ticks_now >= local_metadata.timeout) {
                if (local_metadata.state_0 == NEW) { } 
                else if (local_metadata.state_0 == FREE_PORT_PICKED_UP) {
                    // placeholder for ports.push(flow_ctx.nat_port)
                    ports.write(0, local_metadata.nat_port);

                    local_metadata.state_0 = NEW;
                }
            }
            local_metadata.update_flow_ctx0 = true; 
            exit;  // must explicit the exit!
        } 
        // ######### Stage 0 stateful graph
        else {
            if (local_metadata.state_0 == NEW) {
                if (standard_metadata.ingress_port == INTERNAL) {
                    // placeholder for flow_ctx.nat_port = ports.pop();
                    ports.read(local_metadata.nat_port, 0);
                    local_metadata.stage1_fk = local_metadata.nat_port;

                    // schedule instead of restart?
                    local_metadata.timeout = 
                        local_metadata.ticks_now + CONNECTION_TIMEOUT;

                    //transition free_port_picked_up;
                    local_metadata.state_0 = FREE_PORT_PICKED_UP;
                } else if (standard_metadata.ingress_port == EXTERNAL) {
                    local_metadata.timeout = 
                        local_metadata.ticks_now + CONNECTION_TIMEOUT;

                    local_metadata.stage1_fk = hdr.tcp.dst_port;
                }
            } else if (local_metadata.state_0 == FREE_PORT_PICKED_UP) {
                if (standard_metadata.ingress_port == INTERNAL) {
                    local_metadata.stage1_fk = local_metadata.nat_port;

                    local_metadata.timeout = 
                        local_metadata.ticks_now + CONNECTION_TIMEOUT;
                }
            }
        }
        local_metadata.update_flow_ctx0 = true; 
        // ################## END Stage 0 stateful graph

        local_metadata.use_flow_key1 = 0;
        stage_1.apply();
        
        // ######### Stage 1 stateful graph
        if (local_metadata.state_1 == NEW) {
            if (standard_metadata.ingress_port == INTERNAL) {
                local_metadata.internal_ip_addr = hdr.ipv4.src_addr;
                local_metadata.internal_port  = local_metadata.l4_src_port;

                natIPAddress.read(hdr.ipv4.src_addr, 0);

                if (hdr.tcp.isValid()) { // TCP
                    hdr.tcp.src_port = local_metadata.stage1_fk; 
                } else if (hdr.udp.isValid()) { // UDP
                    hdr.udp.src_port = local_metadata.stage1_fk; 
                }

                standard_metadata.egress_spec = EXTERNAL;

                local_metadata.state_1 = ESTABLISHED;
            } else if (standard_metadata.ingress_port == EXTERNAL) {
                mark_to_drop();
            }
        } else if (local_metadata.state_1 == ESTABLISHED) {
            if (standard_metadata.ingress_port == INTERNAL) {
                natIPAddress.read(hdr.ipv4.src_addr, 0);

                if (hdr.tcp.isValid()){
                    hdr.tcp.src_port = local_metadata.stage1_fk;
                }
                else if (hdr.udp.isValid()){
                    hdr.udp.src_port = local_metadata.stage1_fk; 
                }
                standard_metadata.egress_spec = EXTERNAL;
            }
            else if (standard_metadata.ingress_port == EXTERNAL) {
                hdr.ipv4.dst_addr = local_metadata.internal_ip_addr;
                if (hdr.tcp.isValid()) {
                    hdr.tcp.dst_port = local_metadata.internal_port; 
                }
                else if (hdr.udp.isValid()) {
                    hdr.udp.dst_port = local_metadata.internal_port;
                }
                standard_metadata.egress_spec = INTERNAL;
            }
        }
        local_metadata.update_flow_ctx1 = true; 
        // ################## END Stage 1 stateful graph
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
                            inout local_metadata_t meta) { 

    apply {
        update_checksum(hdr.ipv4.isValid(), 
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                16w0,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            }, 
            hdr.ipv4.hdr_checksum, 
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(hdr.tcp.isValid(), 
            {   
                hdr.ipv4.src_addr, 
                hdr.ipv4.dst_addr, 
                8w0, 
                hdr.ipv4.protocol, 
                meta.tcp_length, 
                hdr.tcp.src_port, 
                hdr.tcp.dst_port, 
                hdr.tcp.seq_no, 
                hdr.tcp.ack_no, 
                hdr.tcp.data_offset, 
                hdr.tcp.res, 
                hdr.tcp.ecn,
                hdr.tcp.ctrl, 
                hdr.tcp.window,
                hdr.tcp.urgent_ptr 
            }, 
            hdr.tcp.checksum, 
            HashAlgorithm.csum16);

    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
