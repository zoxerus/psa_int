#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"


header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totallen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/*
this is the INT-MD shim header added by the source node
for carrying INT-MD metadata over TCP or UDP.
*/
header int_shim_hdr_t {
    /* header type 1 for INT-MD */
    bit<4>  int_type;
    bit<2>  next_protocol;
    bit<2>  reserved;
    /* 
    int_total_length is counted in 4 byte words and doesn't
    include the length of the shim header (1 word).
    */
    bit<8>  int_total_length;
    bit<16> udp_ip_dscp;
}


/* 
This is the INT-MD Metadata header, must be inserted by the source
only, and later editited by the downstream nodes. This header is
then followed by the stack of metadata of each node.
*/
header int_md_hdr_t {
    /* Version = 2 for current spec */
    bit<4>  ver;
    /* 
    Discard: the sink must discard the packet
    after extracting INT-MD metadata
    */   
    bit<1>  d;
    /*
    Max Hop count Exceeded: this bit must be set if the nod 
    can't prepend its own metadate due to Remaining Hop Count
    field reaching zero.
    This bit must be set to zero by INT source.
    */
    bit<1>  e;
    /*
    MTU Exceeded: a node must set this bit if it can't embed its
    INT metadata due to exceeding the egress link MTU.
    */
    bit<1>  m;
    /* Reserved: must be zero */
    bit<12> reserved;
    /*
    Perhop Metadata length: This is the length of metadata 
    including the Domain Specific Metadata in 4-Byte words 
    to be inserted at each INT transit hop.
    Hop ML is set by the INT source for transit and sink hops 
    to abide by.
    */
    bit<5>  hop_metadata_length;
    /*
     The remaining number of hops that are allowed to add their
     metadata to the packet. first set by the source node.
    */
    bit<8>  remaining_hop_count;
    /* 
    Instruction bitmap length = 16 bit divided in four fields
    for ease of handling. named in format xxyy meaning bit xx 
    to bit yy.
    */
    bit<4>  instruction_bitmap_0003;
    bit<4>  instruction_bitmap_0407;
    bit<4>  instruction_bitmap_0811;
    bit<4>  instruction_bitmap_1215;
    /* Domaing Sepcific ID, Instructions, and Flags */
    bit<16> domain_specific_id;
    bit<16> domain_specific_instruction;
    bit<16> domains_specific_flags;
}

/*
A list of the INT-MD to be embedded in the report
each made as a seperate header to be added on demand
according to the instruction bits included in the int_md_hdr header.
*/
header int_node_id_t{
    NodeID node_id;
}
header int_l1_interfaces_t {
    bit<16> ingress_id;
    bit<16> egress_id;
}
header int_hop_latency_t {
    HopLatency hop_latency;
}
header int_queue_info_t {
    QueueID         queue_id;
    QueueOccupancy  queue_occupancy;
}
header int_ingress_timestamp_t {
    Timestamp ingress_timestamp;
}
header int_egress_timestamp_t {
    Timestamp egress_timestamp;
}
header int_l2_interfaces_t {
    L2InterfaceID ingress_id;
    L2InterfaceID egress_id;
}
header int_egress_tx_t {
    InterfaceTxUtilization egress_tx_utilization;
}
header int_buffer_info_t {
    BufferID        buffer_id;
    BufferOccupancy buffer_occupancy;
}
header int_checksum_t {
    ChecksumComplement checksum;
}

header int_metadata_stack_t {
    /* 
    it seems that NIKSS doesn't support varbit,
    128 bits are enough to store the generated MD
    stack for our application,
    */
    /* TODO: change to varbit or set the custom length */
    bit<128> metadata_stack;
}


/*
this is a dummy header to carry the user metadata fron the ingress
to the egress, because copying the user metadata is not yet supported
by the nikss switch.
*/
/* TODO: change to the use of metadata when is supported */
header umeta_t {
    bit<1> isINTSink;
    bit<32> ingress_port;
    bit<64> ingress_timestamp;
    /* padding is used to make the size of the header a multiple of 8 */
    bit<7> padding;
}


struct headers {
    /* 
    a header carrying user metadata not emitted in the 
    final packet.
    */
    umeta_t                 umeta;


    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    udp_t                   udp;
    /*
    Headers for INT-MD Telemetry over TCP or UDP.
    first comes the shim header followed by the int_md header
    then a stack of telemetry metadata.
    */
    int_shim_hdr_t              int_shim;
    int_md_hdr_t                int_md;
    /*
    the metadata stack is used at the sink and it holds the metadata
    inserted by the upstream nodes, it's emitted in the cloned packet
    that goes to the collector and is removed from the original packet
    that goes to the destination host.
    */
    int_metadata_stack_t        int_data;

    /* INT metadata */
    int_node_id_t               int_node_id;
    int_l1_interfaces_t         int_l1_interfaces;
    int_hop_latency_t           int_hop_latency;
    int_queue_info_t            int_queue_info;
    int_ingress_timestamp_t     int_ingress_timestamp;
    int_egress_timestamp_t      int_egress_timestamp;
    int_l2_interfaces_t         int_l2_interfaces;
    int_egress_tx_t             int_egress_tx;
    int_buffer_info_t           int_buffer_info;
    int_checksum_t              int_checksum;
}


#endif // end of #define __HEADERS__