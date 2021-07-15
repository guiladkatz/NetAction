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

state_context ctx_0(bit<8> flow_state_size) {
    bit<64> timeout;
    bool send;
}

#define TIMEOUT_1 1000
#define TIMEOUT_2 2000

state_timer timer_0(inout state_context flow_ctx,
                    inout timer_metadata_t timer_metadata) {
    // apply timer state machine
    if (timer_metadata.ticks_now >= flow_ctx.timeout) {
        state start { 
            // nothing to do
        }

        state alternate {
            // this timer will fire in drop state
            flow_ctx.timeout = timer_metadata.ticks_now + TIMEOUT_1;

            transition drop;
        }
        state drop {
            // this timer will fire in alternate state
            flow_ctx.timeout = timer_metadata.ticks_now + TIMEOUT_2;

            transition alternate;
        }
    }
}


// resolution in us
#define TICK_RESOLUTION 1000 

state_graph graph_0(inout state_context flow_ctx,
                    inout parsed_headers_t hdr,
                    inout local_metadata_t local_metadata,
                    inout standard_metadata_t standard_metadata,
                    inout timer_metadata_t timer_metadata) {
  state start {
    // this timer will fire in alternate state
    flow_ctx.timeout = timer_metadata.ticks_now + 1000; // timeout in ticks

    flow_ctx.send = true;
    transition alternate;
  }

  state alternate {
    if (flow_ctx.send) {
      standard_metadata.egress_spec = 1;
      flow_ctx.send = false;
    } else {
      mark_to_drop();
      flow_ctx.send = true;
    }
  }

  state drop {
    mark_to_drop();
  }
}

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata
                         inout timer_metadata_t timer_metadata) {

    stateful_table stage_0 {
        flow_key[0] = {hdr.ipv4.src, hdr.ipv4.dst, local_metadata.ip_proto, local_metadata.l4_src_port, local_metadata.l4_dst_port};
        flow_cxt = ctx_0(8);
        size = 65536;
        graph = graph_0(flow_ctx, hdr, local_metadata, standard_metadata);
        timer = timer_0(flow_ctx, local_metadata, standard_metadata);
        timer_granularity = TICK_RESOLUTION;  // in microseconds
    }

    apply {
        stage_0.apply(0);
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


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
