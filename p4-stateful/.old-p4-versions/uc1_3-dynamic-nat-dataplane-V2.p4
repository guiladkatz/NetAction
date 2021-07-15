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

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct local_metadata_t {
    bit<8> ip_proto;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bit<16> tcp_length;
    bit<16> nat_port;
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

state_context ctx_0(bit<8> flow_state_size) {
    bit<16> nat_port;
    bit<16> timer_id;
    bit<64> timeout;
}

state_context ctx_1(bit<8> flow_state_size) {
    bit<32> internal_ip_addr; 
    bit<16> internal_port;
}

state_timer timer_0(state_context flow_ctx, 
                    timer_metadata_t timer_metadata,
                    Stack<16> free_ports) {
    if (timer_metadata.ticks_now >= flow_ctx.timeout) {
        state start { }
        state free_port_picked_up {
            ports.push(flow_ctx.nat_port);

            transition start;
        }
    }
}

#define CONNECTION_TIMEOUT 10  //seconds

state_graph graph_0(state_context flow_ctx, 
                    headers_t hdr, 
                    standard_metadata_t standard_metadata,  
                    Stack<bit<16>> ports, 
                    Register<bit<32>> nat_ip_addr) {
    state start {
        if (standard_metadata.ingress_port == INTERNAL) {
            ports.pop(flow_ctx.nat_port);
            local_metadata.stage1_fk = flow_ctx.nat_port;

            flow_ctx.timeout = 
                timer_metadata.ticks_now + CONNECTION_TIMEOUT;

            transition free_port_picked_up;
        }
        else if (standard_metadata.ingress_port == EXTERNAL) {
            local_metadata.timeout = 
                local_metadata.ticks_now + CONNECTION_TIMEOUT;

            local_metadata.stage1_fk = hdr.tcp.dst_port;
        }
    }

    state free_port_picked_up {
        if (standard_metadata.ingress_port == INTERNAL) {
            local_metadata.stage1_fk = flow_ctx.nat_port;
            flow_ctx.timeout = timer_metadata.ticks_now + CONNECTION_TIMEOUT;
        }
    }
}

state_graph graph_1 {
    state start {
        if (standard_metadata.ingress_port == INTERNAL) {
            flow_ctx.internal_ip_addr = hdr.ipv4.src;
            flow_ctx.internal_port = 
                    local_metadata.l4_src_port;

            natIPAddress.read(hdr.ipv4.src_addr, 0); 

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
            natIPAddress.read(hdr.ipv4.src_addr, 0);

            if (hdr.tcp.isValid()){
                hdr.tcp.src = local_metadata.stage1_fk;
                local_metadata.tcp_length = hdr.ipv4.total_len - 16w20;
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

// 1 second resolution
#define TICK_RESOLUTION 1000000 

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata
                         inout timer_metadata_t timer_metadata) {
    
    Stack<bit<16>>(65536) ports; // populated by the control plane at startup
    Register<bit<32>>(1) nat_ip_addr;

    stateful_table stage_0 {
        flow_key[0] = {hdr.ipv4.src, hdr.ipv4.dst, local_metadata.ip_proto, local_metadata.l4_src_port, local_metadata.l4_dst_port};
        flow_cxt = ctx_0(8);
        size = 65536;
        idle_timeout = 120000;
        graph = graph_0(flow_ctx, hdr, standard_metadata, 
                        local_metadata, ports);
        timer = timer_0(flow_ctx, standard_metadata, 
                        timer_metadata, ports,
                        granularity=TICK_RESOLUTION);
    }
       
    stateful_table stage_1 {
        flow_key[0] = {local_metadata.stage1_fk};
        flow_cxt = ctx_1(8);
        size = 65536;
        idle_timeout = 120000;
        graph = graph_1(flow_ctx, hdr, standard_metadata, 
                        local_metadata, nat_ip_addr);
    }

    apply {
        stage_0.apply(0);
        stage_1.apply(0);
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply { //TODO apply checksum }
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t meta)
{
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
                hdr.tcp.flags, 
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
