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

#define NEW 0
#define ESTABLISHED 1
#define LAN 0
#define WAN 1

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {
	
       stateful_element stage_0 {
               flow_key = local_metadata.fk1; //like key in a standard P4 table
               flow_cxt = {bit<32> state;}
               idle_timeout = 30000;
               eviction_policy = LRU;
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
	         if (flow_ctx.state == NEW && standard_metadata.ingress_port == LAN) {
			flow_ctx.state = ESTABLISHED;
			standard_metadata.egress_spec = WAN;
                }
                else if (flow_ctx.state == NEW && standard_metadata.ingress_port == WAN) {
		        mark_to_drop();
                }
                else if (flow_ctx.state == ESTABLISHED) {
	               if (standard_metadata.ingress_port == LAN) {
	                    standard_metadata.egress_spec = WAN;
                      }

                      if (standard_metadata.ingress_port == WAN) {
	                    standard_metadata.egress_spec = LAN;
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