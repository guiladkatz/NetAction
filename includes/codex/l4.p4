/**
    Layer 4 protocol
*/

// standard tcp
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// standard udp
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// VXLAN support 
header vxlan_t {
    bit<8>  flags;          // flags
    bit<16> reserved;       // reserved
    bit<8> next_proto;        // next protocol
    bit<24> vni;            // identifier
    bit<8>  reserved_2;     // reserved
}