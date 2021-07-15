header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
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
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bit<104> fk1;
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

extern bit<32> bitrate_update(in bit<32> block_id, in bit<32> sample);

extern Stack<T> {
    Stack(bit<32> size);
    T pop();
    void push(T value);
    void isEmpty();
}

#define NEW 0
#define NO_BURST 1
#define BURST 2

#define BW 1000 // 1 millisecond?

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    Stack<bit<16>>(65536) rates;
	
    stateful_element stage_0 {
        flow_key = metadata.fk1; //like key in a standard P4 table
        flow_cxt = {
            bit<32> state; 
            bit<64> burst_start_ts;
            bit<64> last_burst_ts;
            bit<64> last_ts;
            bit<32> burst_num; 
            bit<32> burst_size;
            bit<64> burst_separation_avg;
            bit<64> burst_separation_min;
            bit<64> burst_separation_max;
            bit<64> burst_duration_avg;
            bit<64> burst_duration_min;
            bit<64> burst_duration_max;
            bit<32> burst_size_pkt_avg;
            bit<32> burst_size_pkt_min;
            bit<32> burst_size_pkt_max;
            bit<32> burst_rate;
            bit<32> rate_block_id;
        }
        eviction_policy = LRU;
        idle_timeout = 2000000;
        size = 4096;
   	}

	apply {
        if (standard_metadata.ingress_port == 0) {
            local_metadata.fk1 = (hdr.ipv4.src | hdr.ipv4.dst << 32 |
                                   local_metadata.ip_proto << 64 |                                                                  
                                   local_metadata.l4_src_port << 72 |                                   
                                   local_metadata.l4_dst_port << 88);
        } else {
            local_metadata.fk1 = (hdr.ipv4.dst | hdr.ipv4.src << 32 |              
                                   local_metadata.ip_proto << 64 |          
                                   local_metadata.l4_dst_port << 72 |  
                                   local_metadata.l4_src_port << 88);
        }

	    stage_0.apply({
	        if (flow_ctx.state == NEW) {
                flow_ctx.state = NO_BURST;
                flow_ctx.last_ts = standard_metadata.ingress_global_timestamp;

                if (!rates.isEmpty()) {    
                   flow_ctx.rate_block_id = rates.pop();
                } else { } // TODO 
            }

            else if (flow_ctx.state == NO_BURST) {
                bit<64> inter_pkt_duration = standard_metadata.ingress_global_timestamp - flow_ctx.last_ts;

                if (inter_pkt_duration <= BW) { // burst start
                    flow_ctx.burst_num = flow_ctx.burst_num + 1;
                    flow_ctx.burst_rate = rate_update(flow_ctx.rate_block_id, 1); //CHECK for function prototype (in particular the output...)
                    flow_ctx.last_ts = standard_metadata.ingress_global_timestamp;
                    flow_ctx.burst_start_ts = standard_metadata.ingress_global_timestamp;
                    flow_ctx.burst_size = flow_ctx.burst_size + 1;


                    bit<64> burst_separation = standard_metadata.ingress_global_timestamp - 
                                                   flow_ctx.last_burst_ts;

                    flow_ctx.burst_separation_avg = ((flow_ctx.burst_separation_avg * 
                            flow_ctx.burst_num) + burst_separation)/(flow_ctx.burst_num + 1);

                    if (burst_separation >= flow_ctx.burst_separation_max) {
                        flow_ctx.burst_separation_max =  burst_separation;
                    }
                    if (burst_separation < flow_ctx.burst_separation_min || 
                                                flow_ctx.burst_separation_min == 0) {
                        flow_ctx.burst_separation_min = burst_separation;
                    }
                    
                    flow_ctx.state = BURST;
                } else {
                    flow_ctx.last_ts = standard_metadata.ingress_global_timestamp;
                }
            }

            else if (flow_ctx.state == BURST) {
                bit<64> inter_pkt_duration = standard_metadata.ingress_global_timestamp - 
                                                                 flow_ctx.last_ts;
                if (inter_pkt_duration <= BW) { // currently in burst
                    flow_ctx.last_ts = standard_metadata.ingress_global_timestamp;
                    flow_ctx.burst_size = flow_ctx.burst_size + 1;
                    flow_ctx.last_burst_ts = standard_metadata.ingress_global_timestamp;
                } else { // burst completed
                    flow_ctx.last_ts = standard_metadata.ingress_global_timestamp;
                    
                    bit<64> burst_duration = standard_metadata.ingress_global_timestamp - 
                                                                 flow_ctx.burst_start_ts;
                    flow_ctx.burst_duration_avg = ((flow_ctx.burst_duration_avg * 
                        flow_ctx.burst_num) + burst_duration)/(flow_ctx.burst_num + 1)
                    if (burst_duration >= flow_ctx.burst_duration_max) {
                        flow_ctx.burst_duration_max = burst_duration;
                    }
                    if (burst_duration < flow_ctx.burst_duration_min || 
                             flow_ctx.burst_duration_min == 0) {
                        flow_ctx.burst_duration_min = burst_duration;
                    }
                    // TODO: check if avg value is 0, otherwise always 0
                    flow_ctx.burst_size_pkt_avg = ((flow_ctx.burst_size_pkt_avg * 
                        flow_ctx.burst_num) + flow_ctx.burst_size)/(flow_ctx.burst_num + 1)
                    if (flow_ctx.burst_size >= flow_ctx.burst_size_pkt_max) {
                        flow_ctx.burst_size_pkt_max = flow_ctx.burst_size;
                    }
                    if (flow_ctx.burst_size < flow_ctx.burst_size_pkt_min || 
                             flow_ctx.burst_size_pkt_min == 0) {
                        flow_ctx.burst_size_pkt_min = flow_ctx.burst_size;
                    }
                    flow_ctx.state = NO_BURST;
                }            
            }
        });
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
