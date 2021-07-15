struct local_metadata_t {
    bit<8> ip_proto;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bit<16> stage1_fk;
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

#define INTERNAL 0
#define EXTERNAL 1
#define connection_timeout 120000 //120 seconds 

state_context ctx_0 (bit<8> state_size) {
    bit<16> nat_port;
}

state_context ctx_1 (bit<8> state_size) {
    bit<32> internal_ip_addr; 
    bit<16> internal_port;
}

state_graph graph_0(state_context flow_ctx, parsed_headers_t hdr, 
                    local_metadata_t local_metadata, 
                    standard_metadata_t standard_metadata, 
                    register<bit<16>> ports, 
                    register<bit<16>> free_port_pointer) {
    state start {
        if (standard_metadata.ingress_port == INTERNAL) {
            bit<16> tmp_idx = 0;
            free_port_pointer.read(tmp_idx, 0);  

            ports.read(local_metadata.nat_port, 
                        (bit<32>) tmp_idx);

            tmp_idx = tmp_idx + 1;
            free_port_pointer.write(0, tmp_idx);

            local_metadata.stage1_fk = flow_ctx.nat_port;

            transition free_port_picked_up;
        }
        else if (standard_metadata.ingress_port == EXTERNAL) {
            local_metadata.stage1_fk = hdr.tcp.dst_port;
        }
    }

    state free_port_picked_up {
        if (standard_metadata.ingress_port == INTERNAL) {
            local_metadata.stage1_fk = flow_ctx.nat_port;
        }
    }
}

state_graph graph_1(state_context flow_ctx, parsed_headers_t hdr, 
                    local_metadata_t local_metadata, standard_metadata_t standard_metadata, 
                    Register<16> natIPAddress) {
    state start {
        if (standard_metadata.ingress_port == INTERNAL) {
            flow_ctx.internal_ip_addr = hdr.ipv4.src;
            flow_ctx.internal_port  = local_metadata.l4_src_port;

            natIPAddress.read(hdr.ipv4.src, 0);

            if (hdr.tcp.isValid()){
                hdr.tcp.src = local_metadata.stage1_fk; 
            }
            else if (hdr.udp.isValid()){
                hdr.udp.src = local_metadata.stage1_fk; 
            }
            standard_metadata.egress_spec = EXTERNAL;

            transition established;
        } else if (standard_metadata.ingress_port == EXTERNAL) {
            mark_to_drop();
        }
    }

    state established {
        if (standard_metadata.ingress_port == INTERNAL) {
            natIPAddress.read(hdr.ipv4.src, 0);

            if (hdr.tcp.isValid()){
                hdr.tcp.src = local_metadata.stage1_fk; 
            }
            else if (hdr.udp.isValid()){
                hdr.udp.src = local_metadata.stage1_fk; 
            }
            standard_metadata.egress_spec = EXTERNAL;
        }
        else if (standard_metadata.ingress_port == EXTERNAL) {
            hdr.ipv4.dst = flow_ctx.internal_ip_addr;

            if (hdr.tcp.isValid()){
                hdr.tcp.dst = flow_ctx.internal_port; 
            }
            else if (hdr.udp.isValid()){
                hdr.udp.dst = flow_ctx.internal_port;
            }
            standard_metadata.egress_spec = INTERNAL;
        }
    }
}

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {
    
    Register<bit<16>>(65536) ports;
    Register<bit<16>>(1) free_port_pointer;
    Register<bit<32>>(1) natIPAddress;

    stateful_table stage_0 {
        flow_key[0] = {hdr.ipv4.src, hdr.ipv4.dst, local_metadata.ip_proto, local_metadata.l4_src_port, local_metadata.l4_dst_port};
        flow_key[1] = {hdr.ipv4.dst, hdr.ipv4.src, local_metadata.ip_proto, local_metadata.l4_dst_port, local_metadata.l4_src_port};
        flow_cxt = ctx_0(8);
        size = 65536;
        idle_timeout = 120000;
        graph = graph_0(flow_ctx, hdr, local_metadata, 
                        standard_metadata, ports, 
                        free_port_pointer);
    }
       
    stateful_table stage_1 {
        flow_key[0] = {local_metadata.stage1_fk};
        flow_cxt = ctx_1(8);
        size = 65536;
        idle_timeout = 120000;
        graph = graph_1(flow_ctx, hdr, local_metadata, 
                        standard_metadata, natIPAddress);
    }

    apply {
        if (standard_metadata.ingress_port == INTERNAL)
            stage_0.apply(0);
        else
            stage_0.apply(1);

        stage_1.apply(0);
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
