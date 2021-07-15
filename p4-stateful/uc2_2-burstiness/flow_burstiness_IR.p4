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
    bit<8>  ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<8>  state; 
    bit<48> burst_start_ts;
    bit<48> last_burst_ts;
    bit<48> last_ts;
    bit<48> burst_num; 
    bit<48> burst_size;
    bit<48> burst_separation_avg;
    bit<48> burst_separation_min;
    bit<48> burst_separation_max;
    bit<48> burst_duration_avg;
    bit<48> burst_duration_min;
    bit<48> burst_duration_max;
    bit<48> burst_size_pkt_avg;
    bit<48> burst_size_pkt_min;
    bit<48> burst_size_pkt_max;
    bit<48> burst_rate;
    bit<32> meter_id;
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

// 50 ms 
#define INTER_PACKET_GAP 50000

#define START 0
#define NO_BURST 1
#define BURST 2

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1024) available_meters;
    meter(1024, MeterType.packets) burst_rate_meter;

    table stage_0 {
        key = {
            hdr.ipv4.src_addr: exact; 
            hdr.ipv4.dst_addr: exact; 
            local_metadata.ip_proto: exact; 
            local_metadata.l4_src_port: exact; 
            local_metadata.l4_dst_port: exact; 
        }
        actions = {
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        stage_0.apply();

        if (local_metadata.state == START) {
            local_metadata.state = NO_BURST;
            local_metadata.last_ts = 
                standard_metadata.ingress_global_timestamp;

            // stack pop operation
            available_meters.read(local_metadata.meter_id, 32w0);

        } else if (local_metadata.state == NO_BURST) {
            bit<48> inter_pkt_duration = 
                standard_metadata.ingress_global_timestamp - 
                    local_metadata.last_ts;
            if (inter_pkt_duration <= INTER_PACKET_GAP) {
                //local_metadata.burst_rate = rate_update(local_metadata.rate_block_id, 1);
                //burst_rate_meter.execute_meter(local_metadata.rate_block_id, 1); 
                bit<32> mtr_tmp;
                burst_rate_meter.execute_meter(local_metadata.meter_id,
                                                mtr_tmp);
                local_metadata.last_ts = standard_metadata.ingress_global_timestamp;
                local_metadata.burst_start_ts = standard_metadata.ingress_global_timestamp;
                local_metadata.burst_size = local_metadata.burst_size + 1;


                bit<48> burst_separation = 
                        standard_metadata.ingress_global_timestamp - 
                            local_metadata.last_burst_ts;

                // we use | to then change it to "divide" in the json
                local_metadata.burst_separation_avg = 
                        ( (local_metadata.burst_separation_avg * 
                        local_metadata.burst_num) + burst_separation )
                        | (local_metadata.burst_num + 1);

                if (burst_separation >= local_metadata.burst_separation_max) {
                    local_metadata.burst_separation_max =  burst_separation;
                }
                if (burst_separation < local_metadata.burst_separation_min || 
                            local_metadata.burst_separation_min == 0) {
                    local_metadata.burst_separation_min = burst_separation;
                }
                
                local_metadata.state = BURST;
            } else {
                local_metadata.last_ts = 
                    standard_metadata.ingress_global_timestamp;
            }

        } else if (local_metadata.state == BURST) {
            bit<48> inter_pkt_duration = 
                standard_metadata.ingress_global_timestamp - 
                            local_metadata.last_ts;

            if (inter_pkt_duration <= INTER_PACKET_GAP) {
                local_metadata.last_ts = standard_metadata.ingress_global_timestamp;
                local_metadata.burst_size = local_metadata.burst_size + 1;
                local_metadata.last_burst_ts = standard_metadata.ingress_global_timestamp;
            } else { // burst completed
                local_metadata.last_ts = 
                        standard_metadata.ingress_global_timestamp;
                
                bit<48> burst_duration = 
                        local_metadata.last_burst_ts - 
                            local_metadata.burst_start_ts;

                local_metadata.burst_duration_avg = 
                        ( (local_metadata.burst_duration_avg * 
                        local_metadata.burst_num) + burst_duration ) |
                        (local_metadata.burst_num + 1);

                if (burst_duration >= local_metadata.burst_duration_max) {
                    local_metadata.burst_duration_max = burst_duration;
                }
                if (burst_duration < local_metadata.burst_duration_min || 
                         local_metadata.burst_duration_min == 0) {
                    local_metadata.burst_duration_min = burst_duration;
                }

                local_metadata.burst_size_pkt_avg = 
                        ( (local_metadata.burst_size_pkt_avg * 
                        local_metadata.burst_num) + local_metadata.burst_size ) |
                        (local_metadata.burst_num + 1);

                if (local_metadata.burst_size >= 
                        local_metadata.burst_size_pkt_max) {

                    local_metadata.burst_size_pkt_max = 
                            local_metadata.burst_size;
                }
                if ( (local_metadata.burst_size < 
                        local_metadata.burst_size_pkt_min) || 
                        local_metadata.burst_size_pkt_min == 0) {
                    local_metadata.burst_size_pkt_min = local_metadata.burst_size;
                }
                local_metadata.burst_num = local_metadata.burst_num + 1;
                local_metadata.state = NO_BURST;
                local_metadata.burst_size = 0;
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
