
header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_t {
    bit<3> pri;
    bit<1> cfi;
    bit<12> vid;
    bit<16> next_proto;
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

header vxlan_t {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
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
    bit<44> fk1;
}

struct parsed_headers_t {
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    vxlan_t vxlan;
    ipv4_t inner_ipv4;
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0X8100

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
            ETHERTYPE_VLAN: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);

        transition select(hdr.vlan.next_proto) {
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
        select (hdr.udp.dst_port) {
            UDP_PORT_VXLAN: parse_vxlan;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);

        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);

        transition accept;
    }
}

#define DC_NETWORK_PORT 0
#define OTR_0_PORT 1
#define NEW 0
#define LEARNT 1

state_context ctx_0(bit<8> state_size) {
    bit<32> in_flight_cnt; 
    bit<24> vxlan_vni;
} 

state_graph graph_0(state_context flow_ctx, parsed_headers_t hdr, 
                    local_metadata_t local_metadata, 
                    standard_metadata_t standard_metadata) {

    // This can also be implemented by inserting the port as a 
    // field in the flow key
    state start {
        if (standard_metadata.ingress_port == OTR_0_PORT) {
            //learn
            flow_ctx.vxlan_vni = hdr.vxlan.vni;

            flow_ctx.outer_ip_dst = hdr.ipv4.dst_addr;
            // TODO: maybe the source address is unique? can we store it in a global reg?
            flow_ctx.outer_ip_src = hdr.ipv4.src_addr;
            // TODO: maybe also udp source is always the same?
            flow_ctx.outer_udp_src = hdr.udp.src_port;

            standard_metadata.egress_spec = DC_NETWORK_PORT;

            transition learnt;
        } else if (standard_metadata.ingress_port != OTR_0_PORT) {
            fwd_to_otr();
            flow_ctx.in_flight_cnt = flow_ctx.in_flight_cnt + 1;
        }
    }

    state learnt {
        if (standard_metadata.ingress_port != OTR_0_PORT) {
            flow_ctx.in_flight_cnt = flow_ctx.in_flight_cnt - 1;
            standard_metadata.egress_spec = DC_NETWORK_PORT;
        } else if (standard_metadata.ingress_port != OTR_0_PORT) {
            if (flow_ctx.in_flight_cnt == 0) {
                encap_to_dc_network(flow_ctx.vxlan_id);
            } else {
                fwd_to_otr();
                flow_ctx.in_flight_cnt = flow_ctx.in_flight_cnt + 1;
            }
        }
    }
}

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    stateful_table stage_0 {
        flow_key[0] = {hdr.vxlan.reserved2, hdr.inner_ipv4.dst_addr};
        flow_key[1] = {hdr.vlan.vid, hdr.ipv4.dst_addr};        
        flow_cxt = ctx_0(8);
        idle_timeout = 30000;
        eviction_policy = LFU;
        size = 4096;
        graph = graph_0(flow_ctx, hdr, local_metadata, standard_metadata);
    }

    action decap_and_fwd_to_bm_server(bit<9> output_port, bit<12> vid) {
        hdr.ipv4.version = hdr.inner_ipv4.version;
        hdr.ipv4.ihl = hdr.inner_ipv4.ihl;
        hdr.ipv4.dscp = hdr.inner_ipv4.dscp;
        hdr.ipv4.ecn = hdr.inner_ipv4.ecn;
        hdr.ipv4.total_len = hdr.inner_ipv4.total_len;
        hdr.ipv4.identification = hdr.inner_ipv4.identification;
        hdr.ipv4.flags = hdr.inner_ipv4.flags;
        hdr.ipv4.frag_offset = hdr.inner_ipv4.frag_offset;
        hdr.ipv4.ttl = hdr.inner_ipv4.ttl;
        hdr.ipv4.protocol = hdr.inner_ipv4.protocol;
        hdr.ipv4.hdr_checksum = hdr.inner_ipv4.hdr_checksum;
        hdr.ipv4.src_addr = hdr.inner_ipv4.src_addr;
        hdr.ipv4.dst_addr = hdr.inner_ipv4.dst_addr;

        hdr.inner_ipv4.setInvalid();
        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();

        hdr.vlan.setValid();
        hdr.vlan.pri = 0; 
        hdr.vlan.cfi = 0;
        hdr.vlan.vid = vid;
        hdr.vlan.next_proto = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;

        standard_metadata.egress_spec = output_port;
    }

    action encap_to_dc_network(bit<24> vxlan_vni, bit<32> src_ip_addr, bit<32> dst_ip_addr, bit<16> udp_src_port) {
        hdr.udp.setValid();
        hdr.vxlan.setValid();
        hdr.inner_ipv4.setValid();

        hdr.udp.src_port = udp_src_port;
        hdr.udp.dst_port = UDP_PORT_VXLAN;
        hdr.udp.len = hdr.ipv4.total_len + 8 + 8;

        hdr.vxlan.flags = 0b00001000;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = vxlan_vni;
        hdr.vxlan.reserved2 = 0;

        hdr.inner_ipv4.version          = hdr.ipv4.version;
        hdr.inner_ipv4.ihl              = hdr.ipv4.ihl;
        hdr.inner_ipv4.dscp             = hdr.ipv4.dscp;
        hdr.inner_ipv4.ecn              = hdr.ipv4.ecn;
        hdr.inner_ipv4.total_len        = hdr.ipv4.total_len;
        hdr.inner_ipv4.identification   = hdr.ipv4.identification;
        hdr.inner_ipv4.flags            = hdr.ipv4.flags;
        hdr.inner_ipv4.frag_offset      = hdr.ipv4.frag_offset;
        hdr.inner_ipv4.ttl              = hdr.ipv4.ttl;
        hdr.inner_ipv4.protocol         = hdr.ipv4.protocol;
        hdr.inner_ipv4.hdr_checksum     = hdr.ipv4.hdr_checksum;
        hdr.inner_ipv4.src_addr         = hdr.ipv4.src_addr;
        hdr.inner_ipv4.dst_addr         = hdr.ipv4.dst_addr;

        hdr.ipv4.src_addr = src_ip_addr;
        hdr.ipv4.dst_addr = dst_ip_addr;
        hdr.ipv4.total_len = hdr.ipv4.total_len + 8 + 20 + 8;

        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();

    }

    action fwd_to_otr() {
        standard_metadata.egress_spec = OTR_0_PORT;
    }

    table from_dc_network {
        key = {hdr.ipv4.dst_addr: exact;}
        actions = {
            decap_and_fwd_to_bm_server;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        if (standard_metadata.ingress_port == DC_NETWORK_PORT) {
            from_dc_network.apply();
        }

        else {
            // flow key creation
            if (standard_metadata.ingress_port == OTR_0_PORT) {
                stage_0.apply(0);
            } else {
                stage_0.apply(1);
            }
        }
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
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ipv4);
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
