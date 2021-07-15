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
}

struct queue_metadata_t {
    bit<8> qdepth_0;
    bit<8> qdepth_1;
    bit<8> qdepth_2;
    bit<8> qdepth_3;
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

// 1 ms
#define TICK_RESOLUTION 1000 

#define NEW 0
#define ALTERNATE 1
#define DROP 2

// if queue depth > 16 we trigger the early update actions
#define QDEPTH_THRESHOLD 16

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;

#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)

state_context_t ctx_0(bit<8> state_size) {
    bit<8> qdepth;
    bit<8> qdepth_diff_mod;
    bool qd_diff_positive;
    bit<9> egress_port;
}

state_timer timer_0(inout state_context flow_ctx,
                    inout timer_metadata_t t_meta,
                    inout queue_metadata_t queue_metadata) {
    state start {
        bit<8> tmp;
        if (flow_ctx.egress_port == 0) {
            tmp = queue_metadata.qdepth_0;
        } else if (flow_ctx.egress_port == 1) {
            tmp = queue_metadata.qdepth_1;
        }

        if (flow_ctx.qdepth >= tmp) {
            flow_ctx.qdepth_diff_mod = flow_ctx.qdepth - tmp;
            flow_ctx.qd_diff_positive = false;
        } else {
            flow_ctx.qdepth_diff_mod = tmp - flow_ctx.qdepth;
            flow_ctx.qd_diff_positive = true;
        }

        flow_ctx.qdepth = tmp;
    }
}

state_graph graph_0(inout state_context_t flow_ctx,
                    inout parsed_headers_t hdr,
                    inout standard_metadata_t standard_metadata,
                    inout local_metadata_t local_metadata) {

    if (IS_RECIRCULATED(standard_metadata.instance_type)) {
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

        // TODO: send also queue info?
    } else {
        state start {
            flow_ctx.egress_port = standard_metadata.egress_spec;

            if (flow_ctx.qdepth > QDEPTH_THRESHOLD) {
                transition congestion;
            } else {
                transition no_congestion;
            }
        }

        state no_congestion {
            // nothing
            if (flow_ctx.qdepth > QDEPTH_THRESHOLD) {
                transition congestion;
            }
        }

        state congestion {
            if (flow_ctx.qdepth > QDEPTH_THRESHOLD) {
                // queue depth is increasing (positive)
                if (flow_ctx.qd_diff_positive) {
                    // do something when increasing
                    clone3(CloneType.I2E, 0, standard_metadata);
                } else { // queue depth is decreasing (non-positive)
                    // do something when decreasing
                }
            } else { // no more over threshold
                transition no_congestion;
            }
        }
    }
}

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    table stage_0 {
        flow_key[0] = {
            standard_metadata.egress_spec;
        };
        flow_ctx = ctx_0(8);
        size = 1024;
        graph = graph_0(flow_ctx,
                    hdr,
                    standard_metadata,
                    local_metadata);
        timer = timer_0(flow_ctx,
                    standard_metadata, 
                    local_metadata,
                    res=TICK_RESOLUTION);        
    }

    apply {
        if (standard_metadata.ingress_port == 0) {
            standard_metadata.egress_spec = 1;
        } else {
            standard_metadata.egress_spec = 0;
        }

        stage_0.apply(0);
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
