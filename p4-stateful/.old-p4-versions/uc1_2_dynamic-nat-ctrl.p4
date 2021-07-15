struct local_metadata_t {
    bit<8> ip_proto;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bit<104> fk1;
    bit<16> nat_port;
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

#define internal 0
#define external 1
#define connection_timeout 120000 //120 seconds 

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {
    
    Register<bit<16>>(65536) ports;
    Register<bit<16>>(1) freePortPointer;

    stateful_element stage_0 {
        flow_key = local_metadata.fk1;
        flow_cxt = {
            bit<32> state; 
            bit<16> nat_port;
        }
        size = 65536;
        idle_timeout = 120000;
    }
       
    stateful_element stage_1 {
        flow_key = local_metadata.fk2;
        flow_cxt = {
            bit<32> state; 
            bit<32> internal_ip_addr; 
            bit<16> internal_port;
        }
        idle_timeout = 120000;
        size = 65536;
    }

    apply {
        local_metadata.fk1 = (hdr.ipv4.src | hdr.ipv4.dst << 32 |
                                   local_metadata.ip_proto << 64 |                                                                  
                                   local_metadata.l4_src_port << 72 |                                   
                                   local_metadata.l4_dst_port << 88);

        stage_0.apply({
            if (flow_ctx.state == 0 && standard_metadata.ingress_port == internal) {
                flow_ctx.nat_port = ports.read(freePortPointer.read(0)); //TODO Use temp register
                local_metadata.fk2 = flow_ctx.nat_port;

                bit<16> tmp = freePortPointer.read(0) + 1;   //check for buffer overflow
                freePortID.write(0, tmp);
            }
            else if (flow_ctx.state == 0 && standard_metadata.ingress_port == external) {
                local_metadata.fk2 = local_metadata.l4_dst_port;
            }
            else if (flow_ctx.state == 1 && standard_metadata.ingress_port == internal) {
                local_metadata.fk2 = flow_ctx.nat_port;
            }
            //TODO STATE 1 from external port
        });


        stage_1.apply({
            if (flow_ctx.state == 0 && standard_metadata.ingress_port == internal) {
                flow_ctx.state = 1;
                flow_ctx.internal_ip_addr = hdr.ipv4.src;
                flow_ctx.internal_port  = local_metadata.l4_src_port;
                hdr.ipv4.src = natIPAddress.read(0); 
                if (hdr.tcp.isValid()){
                    hdr.tcp.src = local_metadata.fk2; 
                }
                else if (hdr.udp.isValid()){
                    hdr.udp.src = local_metadata.fk2; 
                }
                standard_metadata.egress_spec = external;
            }
            else if (flow_ctx.state == 0 && standard_metadata.ingress_port == external) {
                mark_to_drop();
            }
            else if (flow_ctx.state == 1 && standard_metadata.ingress_port == internal) {
                hdr.ipv4.src = natIPAddress.read(0); 
                if (hdr.tcp.isValid()){
                    hdr.tcp.src = local_metadata.fk2; 
                }
                else if (hdr.udp.isValid()){
                    hdr.udp.src = local_metadata.fk2; 
                }
                standard_metadata.egress_spec = external;
            }
            else if (flow_ctx.state == 1 && standard_metadata.ingress_port == external) {
                hdr.ipv4.dst = flow_ctx.internal_ip_addr;
                if (hdr.tcp.isValid()){
                    hdr.tcp.dst = flow_ctx.internal_port; 
                }
                else if (hdr.udp.isValid()){
                hdr.udp.dst = flow_ctx.internal_port;
                }
                standard_metadata.egress_spec = internal;
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
