#ifndef __INGRESS__
#define __INGRESS__

#include "md_insert.p4"

/* The Ingress Control Block */
control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) int_src_counter;
    DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) forward_counter;

    DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) int_sink_counter;


    /* basic forwarding based on IPv4 */
    action do_forward(PortId_t egress_port, EthernetAddress srcAddr,
     EthernetAddress dstAddr) {

        /* increase packet counter by one */
        forward_counter.count();

        /* 
        Carrying the user metadata in a dummy header instead of the usual struct
        due to limitation in the ability to copy the user metedata struct from ingress
        to egress.
        */
        /* TODO: decide wheter to keep or remove this */
        hdr.umeta.ingress_timestamp = (bit<64>) istd.ingress_timestamp;
        hdr.umeta.ingress_port =  (bit<32>) istd.ingress_port;


        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        
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
        
        /* increase INT source counter by one */
        int_src_counter.count();

        /* 
        as this is a source INT, add the shim header and set
        the relevant values 
        */
        hdr.int_shim.setValid();
        hdr.int_shim.int_type = 1;
        hdr.int_shim.next_protocol = 0;
        hdr.int_shim.reserved = 0;
        hdr.int_shim.int_total_length = 3;
        hdr.int_shim.udp_ip_dscp = ( (bit<16>) hdr.ipv4.dscp ) << 2;

        /* 
        Setting the DSCP field to indicate for downstream nodes
        that this packet is carrying INT data.
        */
        hdr.ipv4.dscp = DSCP_INT;

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

        /*
        increase UDP and IPv4 lengths by 16 bytes 
        (4 bytes shim, and 12 bytes INT header)
        */
        hdr.udp.length_ = hdr.udp.length_ + 16w16;
        hdr.ipv4.totallen = hdr.ipv4.totallen + 16w16;

    }

    action set_sink(CloneSessionId_t csi, PortId_t port){
        int_sink_counter.count();

        /*
        setting a flag in the dummy header to indicate that this
        node is a sink node for the INT.
        */
        hdr.umeta.isINTSink = 1w1;

        /* mark the packet to be cloned to the egress */
        ostd.clone = true;
        ostd.clone_session_id = csi;
        send_to_port(ostd, port);
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
        psa_direct_counter = int_src_counter;
        size = 100;
    }

    /* Table for detecting if this is an INT sink */
    table tbl_role_sink{
        key = {
            hdr.ipv4.dstAddr    : exact;
            hdr.udp.srcPort     : exact;
            ostd.egress_port    : exact;
        }
        actions = {set_sink; NoAction;}
        default_action = NoAction;
        psa_direct_counter = int_sink_counter;
        size = 100;
    }

    /* Table for forwarding the packet based on IPv4 header */
    table tbl_fwd {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = { do_forward; NoAction; }
        default_action = NoAction;
        psa_direct_counter = forward_counter;
        size = 100;
    }

    apply {
        /* header must be made valid to be emitted in the deparser */
        hdr.umeta.setValid();
        if (tbl_fwd.apply().hit) {
            /* 
            tbl_role_source: detect if node is a source for INT,
            set the relevant metadata and add the shim header.
            */
            tbl_role_source.apply();
            /*
            detect if node is an INT sink, to clone the packet I2E
            */
            tbl_role_sink.apply();
        }
    }

}  // end of ingress


#endif // __INGRESS__