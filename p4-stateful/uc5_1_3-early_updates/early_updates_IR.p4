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

//Custom metadata definition
struct local_metadata_t {
    bit<8> ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<64> ticks_now;
    bool update_flow_ctx;
    bit<8> qdepth_0;
    bit<8> qdepth_1;
    bit<8> state;
    bit<9> egress_port;
    bit<8> qdepth_now;
    bit<8> qdepth_diff_mod;
    bool qd_diff_positive;
}

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
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
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }
}

// 1 ms
#define TICK_RESOLUTION 1000 
#define QDEPTH_THRESHOLD 16

#define NEW 0
#define NO_CONGESTION 1
#define CONGESTION 2

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;

#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)


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
        if (standard_metadata.ingress_port == 0) {
            standard_metadata.egress_spec = 1;
        } else {
            standard_metadata.egress_spec = 0;
        }

        stage_0.apply();

        //if (timer.ticks_now == flow_ctx.timeout) {
        if (standard_metadata.ingress_port == 200) {
            bit<8> tmp;
            if (local_metadata.egress_port == 0) {
                tmp = local_metadata.qdepth_0;
            } else {
                tmp = local_metadata.qdepth_1;
            }

            if (local_metadata.qdepth_now >= tmp) {
                local_metadata.qdepth_diff_mod = local_metadata.qdepth_now - tmp;
                local_metadata.qd_diff_positive = false;
            } else {
                local_metadata.qdepth_diff_mod = tmp - local_metadata.qdepth_now;
                local_metadata.qd_diff_positive = true;
            }

            local_metadata.qdepth_now = tmp;
            local_metadata.update_flow_ctx = true;
        } else {
            if (IS_RECIRCULATED(standard_metadata)) {
                standard_metadata.egress_spec = 
                        standard_metadata.ingress_port;

                // send probe information back to sender

                bit<32> ip_tmp = hdr.ipv4.src_addr;
                hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
                hdr.ipv4.dst_addr = ip_tmp;

                bit<16> tcp_tmp = hdr.tcp.src_port;
                hdr.tcp.src_port = hdr.tcp.dst_port;
                hdr.tcp.dst_port = tcp_tmp;

                hdr.tcp.ecn = 0b11;

                local_metadata.update_flow_ctx = true;

                // TODO: send also queue info?
            } else {
                if (local_metadata.state == NEW) {
                    local_metadata.egress_port = standard_metadata.egress_spec;

                    if (local_metadata.qdepth_now > QDEPTH_THRESHOLD) {
                        local_metadata.state = CONGESTION;
                    } else {
                        local_metadata.state = NO_CONGESTION;
                    }
                }

                if (local_metadata.state == NO_CONGESTION) {
                    // nothing
                    if (local_metadata.qdepth_now > QDEPTH_THRESHOLD) {
                        local_metadata.state = CONGESTION;
                    }
                }

                if (local_metadata.state == CONGESTION) {
                    if (local_metadata.qdepth_now > QDEPTH_THRESHOLD) {
                        // queue depth is increasing (positive)
                        if (local_metadata.qd_diff_positive) {
                            // do something when increasing
                            clone3(CloneType.I2E, 0, standard_metadata);
                        } else { // queue depth is decreasing (non-positive)
                            // do something when decreasing
                        }
                    } else { // no more over threshold
                        local_metadata.state = NO_CONGESTION;
                    }
                }
                local_metadata.update_flow_ctx = true;
            }
        } 
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        if (IS_I2E_CLONE(standard_metadata)) {
            recirculate(standard_metadata);
        }
    }
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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
