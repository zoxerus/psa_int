#include <core.p4>
#include <psa.p4>

#define ETH_TYPE_IPV4 16w2048
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define DSCP_INT 6w23

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;
typedef bit<16>  L4Port;

typedef bit<32>  NodeID;
typedef bit<16>  L1InterfaceID;
typedef bit<32>  HopLatency;
typedef bit<64>  Timestamp;
typedef bit<8>   QueueID;
typedef bit<24>  QueueOccupancy;
typedef bit<32>  L2InterfaceID;
typedef bit<32>  InterfaceTxUtilization;
typedef bit<8>   BufferID;
typedef bit<24>  BufferOccupancy;
typedef bit<32>  ChecksumComplement;


struct metadata {
    /*
    variable for storing the length of the telemetry stack 
    including int_md_header excluding the shim header.
    */
    bit<8> intShimLength;
    bool isSource;
    bool isTransit;
    bool isSink;
    PortId_t ingress_port;
    NodeID node_id;
    bit<64> ingress_timestamp;
    bit<16> new_bytes;
    bit<8>  new_words;
    bit<8>  int_shim_len;
}


struct empty_t {}

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
    PortId_t ingress_id;
    PortId_t egress_id;
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

// header int_metadata_stack_t {
//     /* enough room to store full metadata of 4 nodes */
//     varbit<1650> metadata_stack;
// }


struct headers {
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

/* The Ingress Parser */
parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            ETH_TYPE_IPV4:  parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol){
            IP_PROTO_UDP:   parse_udp;
            default:        accept;
        }
    }

    state parse_udp {
        buffer.extract(parsed_hdr.udp);
        transition select(parsed_hdr.ipv4.dscp){
            DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_int {
        buffer.extract(parsed_hdr.int_shim);
        buffer.extract(parsed_hdr.int_md);
        /* int_total_length doesn't include the shim header (1 word) */
        meta.int_shim_len = parsed_hdr.int_shim.int_total_length;
        transition accept;
    }
} // end of IngressParserImpl

/* The Ingress Control Block */
control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    /* basic forwarding based on IPv4 */
    action do_forward(PortId_t egress_port) {
        /* record ingress timestamp_t for INT processing */
        meta.ingress_timestamp = (bit<64>) istd.ingress_timestamp;
        /* set the egress interface */
        send_to_port(ostd, egress_port);
    }

    /*
    Action for setting the node as INT source. 
    mdLen: length of node metadata to be inserted
    remHops: number of remaining nodes that are allowed
    to add their md including the current node.
    iBitx: part x of the instruction bitmap, as the instruction
    bitmap is divided into x parts for ease of handling.
    */
    action set_source (
            bit<5> mdLen, bit<8> remHops, bit<4> iBit0, 
            bit<4> iBit1, bit<4> iBit2, bit<4>iBit3

            ) 
        {
        /* 
        Indicate that this is node is source node for INT-MD
        used two types of metadata for experimental reasons,
        */
        // TODO: Remove redundant metadata.
        meta.isSource = true;

        /* as this is a source INT, add the shim header */
        hdr.int_shim.setValid();
        hdr.int_shim.int_type = 1;
        hdr.int_shim.next_protocol = 0;
        hdr.int_shim.reserved = 0;
        hdr.int_shim.int_total_length = 0;
        hdr.int_shim.udp_ip_dscp = (bit<16>) hdr.ipv4.dscp << 2;

        /* add the INT-MD metadata header */
        hdr.int_md.setValid();
        hdr.int_md.ver = 2;
        hdr.int_md.d = 0;
        hdr.int_md.e = 0;
        hdr.int_md.m = 0;
        hdr.int_md.reserved = 0;
        hdr.int_md.hop_metadata_length = mdLen;
        hdr.int_md.remaining_hop_count = remHops;
        /* 
        the instruction bitmap is divided into four 4-bit words
        for ease of handling.
        */
        hdr.int_md.instruction_bitmap_0003 = iBit0;
        hdr.int_md.instruction_bitmap_0407 = iBit1;
        hdr.int_md.instruction_bitmap_0811 = iBit2;
        hdr.int_md.instruction_bitmap_1215 = iBit3;
        /*
        set any domain specific info to zero as we have only one
        INT domain.
        */
        // TODO: expand the action to set the DS fields.
        hdr.int_md.domain_specific_id = 0;
        hdr.int_md.domain_specific_instruction = 0;
        hdr.int_md.domains_specific_flags = 0;
    }

    /* Table for detecting if this is an INT source */
    table tbl_role_source{
        key = {
            hdr.ipv4.srcAddr    : exact;
            hdr.udp.srcPort     : exact;
            istd.ingress_port   : exact;
        }
        actions = {set_source; NoAction;}
        default_action = NoAction;
        size = 100;
    }

    /* Table for forwarding the packet based on IPv4 header */
    table tbl_fwd {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = { do_forward; NoAction; }
        default_action = NoAction;
        size = 100;
    }

    apply {

        if (tbl_fwd.apply().hit) {
            /* 
            tbl_role_source: detect if node is a source for INT,
            set the relevant metadata and add the shim header.
            */
            tbl_role_source.apply();
        }
    }

}  // end of ingress


/* Ingress Deparser */
control IngressDeparserImpl(packet_out buffer,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    // CommonDeparserImpl() cp;
    apply {
        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
        buffer.emit(hdr.udp);
        buffer.emit(hdr.int_shim);
        buffer.emit(hdr.int_md);
    }
}


/* The Egress Parser */
parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            ETH_TYPE_IPV4:  parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol){
            IP_PROTO_UDP:   parse_udp;
            default:        accept;
        }
    }

    state parse_udp {
        buffer.extract(parsed_hdr.udp);
        transition select(parsed_hdr.ipv4.dscp){
            DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_int {
        buffer.extract(parsed_hdr.int_shim);
        buffer.extract(parsed_hdr.int_md);
        /* int_total_length doesn't include the shim header (1 word) */
        meta.int_shim_len = parsed_hdr.int_shim.int_total_length;
        transition accept;
    }
} // end of EgressParserImpl


/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    action clone_packet(CloneSessionId_t csi){
        ostd.clone = true;
        ostd.clone_session_id = csi;
    }

        /* configure Node Role and set Node ID */
    action init_metadata(NodeID node_id) {
        meta.isTransit = true;
        meta.node_id = node_id;
    }

    /* Node ID, 4 bytes */
    @hidden
    action int_set_header_0() {
        hdr.int_node_id.setValid();
        hdr.int_node_id.node_id = meta.node_id;
    }
    
    /* L1 Interface Info, 4 byte each */
    @hidden
    action int_set_header_1() {
        hdr.int_l1_interfaces.setValid();
        hdr.int_l1_interfaces.ingress_id = 
                                    (PortId_t) meta.ingress_port;
        hdr.int_l1_interfaces.egress_id = 
                                    (PortId_t) istd.egress_port;
    }

    /* set Hope Latency 4 bytes */
    @hidden
    action int_set_header_2() {
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>) (
            (bit<64>) istd.egress_timestamp - meta.ingress_timestamp
        );
    }

    /* Queue Info 4 bytes, Currently not supported in PSA */
    @hidden
    action int_set_header_3() {
        // TODO: Support queue info
        hdr.int_queue_info.setValid();
        /* queue_id: 8 bits */
        hdr.int_queue_info.queue_id = 0;

        /* 
        queue occupancy 24 bits, not supported currently.
        use a random number instead ?
        */
        hdr.int_queue_info.queue_occupancy = 0;
    }

    /* Ingress Timestamp 8 bytes */
    @hidden
    action int_set_header_4() {
        hdr.int_ingress_timestamp.setValid();
        hdr.int_ingress_timestamp.ingress_timestamp =
            meta.ingress_timestamp;
    }

    /* Egress Timestamp 8 bytes */
    @hidden
    action int_set_header_5() {
        hdr.int_egress_timestamp.setValid();
        hdr.int_egress_timestamp.egress_timestamp =
            (bit<64>) istd.egress_timestamp;
    }

    /* L2 Port IDs 8 byte total 4 byte each */
    @hidden
    action int_set_header_6() {
        // TODO: Support L2 Port IDs.
        hdr.int_l2_interfaces.setValid();
        hdr.int_l2_interfaces.ingress_id = 0;
        hdr.int_l2_interfaces.egress_id = 0;
    }

    /* Egress Port Tx utilization */
    @hidden
    action int_set_header_7() { 
        // TODO: implement tx utilization support
        hdr.int_egress_tx.setValid();
        hdr.int_egress_tx.egress_tx_utilization = 0;
    }

    /* Buffer Info */
    @hidden
    action int_set_header_8() { 
        // TODO: implement buffer support
        hdr.int_buffer_info.setValid();
        hdr.int_buffer_info.buffer_id = 0;
        hdr.int_buffer_info.buffer_occupancy = 0;
    }

    // Actions to keep track of the new metadata added.
    @hidden
    action add_1() {
        meta.new_words = meta.new_words + 1;
        meta.new_bytes = meta.new_bytes + 4;
    }

    @hidden
    action add_2() {
        meta.new_words = meta.new_words + 2;
        meta.new_bytes = meta.new_bytes + 8;
    }

    @hidden
    action add_3() {
        meta.new_words = meta.new_words + 3;
        meta.new_bytes = meta.new_bytes + 12;
    }

    @hidden
    action add_4() {
        meta.new_words = meta.new_words + 4;
       meta.new_bytes = meta.new_bytes + 16;
    }

    @hidden
    action add_5() {
        meta.new_words = meta.new_words + 5;
        meta.new_bytes = meta.new_bytes + 20;
    }

    /* 
    actions for bits 0-3 combinations, 0 is msb, 3 is lsb
    Each bit set indicates that corresponding INT header should be added 
    */
    @hidden
     action int_set_header_0003_i0() {

     }
    @hidden
     action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    @hidden
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    @hidden
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    @hidden
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
    @hidden
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    @hidden
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    @hidden
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    @hidden
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
    @hidden
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    @hidden
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }

     /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    @hidden
    action int_set_header_0407_i0() {
    }
    @hidden
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    @hidden
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    @hidden
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    @hidden
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_1();
    }
    @hidden
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_2();
    }
    @hidden
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_3();
    }
    @hidden
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    @hidden
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_1();
    }
    @hidden
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_2();
    }
    @hidden
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_3();
    }
    @hidden
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_2();
    }
    @hidden
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_3();
    }
    @hidden
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
    @hidden
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }

    // Default action used to set switch ID.
    table tb_int_insert {
        // We don't really need a key here, however we add a dummy one as a
        // workaround to ONOS inability to properly support default actions.
        key = {
            hdr.int_shim.isValid(): exact @name("int_is_valid");
        }
        actions = {
            init_metadata;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        size = 1;
    }

    /* Table to process instruction bits 0-3 */
    @hidden
    table tb_int_inst_0003 {
        key = {
            hdr.int_md.instruction_bitmap_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        const entries = {
            (0x0) : int_set_header_0003_i0();
            (0x1) : int_set_header_0003_i1();
            (0x2) : int_set_header_0003_i2();
            (0x3) : int_set_header_0003_i3();
            (0x4) : int_set_header_0003_i4();
            (0x5) : int_set_header_0003_i5();
            (0x6) : int_set_header_0003_i6();
            (0x7) : int_set_header_0003_i7();
            (0x8) : int_set_header_0003_i8();
            (0x9) : int_set_header_0003_i9();
            (0xA) : int_set_header_0003_i10();
            (0xB) : int_set_header_0003_i11();
            (0xC) : int_set_header_0003_i12();
            (0xD) : int_set_header_0003_i13();
            (0xE) : int_set_header_0003_i14();
            (0xF) : int_set_header_0003_i15();
        }
    }

    /* Table to process instruction bits 4-7 */
    @hidden
    table tb_int_inst_0407 {
        key = {
            hdr.int_md.instruction_bitmap_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        const entries = {
            (0x0) : int_set_header_0407_i0();
            (0x1) : int_set_header_0407_i1();
            (0x2) : int_set_header_0407_i2();
            (0x3) : int_set_header_0407_i3();
            (0x4) : int_set_header_0407_i4();
            (0x5) : int_set_header_0407_i5();
            (0x6) : int_set_header_0407_i6();
            (0x7) : int_set_header_0407_i7();
            (0x8) : int_set_header_0407_i8();
            (0x9) : int_set_header_0407_i9();
            (0xA) : int_set_header_0407_i10();
            (0xB) : int_set_header_0407_i11();
            (0xC) : int_set_header_0407_i12();
            (0xD) : int_set_header_0407_i13();
            (0xE) : int_set_header_0407_i14();
            (0xF) : int_set_header_0407_i15();
        }
    }


    /* Table for detecting if this is an INT Sink */
    table tbl_sink_clone{
        key = {
            hdr.ipv4.dstAddr   : exact;
            hdr.udp.srcPort    : exact;
            istd.egress_port   : exact;
        }
        actions = {clone_packet; NoAction;}
        default_action = NoAction;
        size = 100;
    }
    apply {
        /* 
        a table for setting switch id and role in the local_metadata.
        */
        if (tb_int_insert.apply().hit) {
            /*
            tb_int_inst_0003 is for bits 0-3 of the instruction bitmap
            tb_int_inst_0407 is for bits 4-7 of the instruction bitmap
            read the instructions from the INT header and append metadata.
            */
            tb_int_inst_0003.apply();
            tb_int_inst_0407.apply();

            // Decrement remaining hop count
            hdr.int_md.remaining_hop_count = hdr.int_md.remaining_hop_count - 1;

            // Update headers lengths.

            hdr.ipv4.totallen = hdr.ipv4.totallen + meta.new_bytes;


            hdr.udp.length_ = hdr.udp.length_ + meta.new_bytes;


            hdr.int_shim.int_total_length = hdr.int_shim.int_total_length + meta.new_words;
        }
        tbl_sink_clone.apply();
     }
} // end of egress



control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{

    apply {
        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
        buffer.emit(hdr.udp);
        buffer.emit(hdr.int_shim);
        buffer.emit(hdr.int_md);
        buffer.emit(hdr.int_node_id);
        buffer.emit(hdr.int_l1_interfaces);
        buffer.emit(hdr.int_hop_latency);
        buffer.emit(hdr.int_queue_info);
        buffer.emit(hdr.int_ingress_timestamp);
        buffer.emit(hdr.egress_timestamp);
        buffer.emit(hdr.int_l2_interfaces);
        buffer.emit(hdr.int_egress_tx);
        buffer.emit(hdr.int_buffer_info);
        buffer.emit(hdr.int_checksum);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;



EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;


PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;