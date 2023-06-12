#ifndef __INGRESS__
#define __INGRESS__

// #include "md_insert.p4"

/* The Ingress Control Block */
control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    // DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) int_src_counter;
    // DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) forward_counter;
    // DirectCounter<bit<32>>(PSA_CounterType_t.PACKETS) int_sink_counter;

    Register<bit<64>, bit<8>>(32w6) reg_flow_byte_count;
    Register<bit<32>, bit<8>>(32w6) reg_flow_packet_count;
    Register<bit<32>, bit<8>>(32w1) reg_node_id;

    bit<8> zero;

    @hidden
    action add_int_metadata(PortId_t egress_port, bit<8> flow_id){
        zero = 8w0;

        hdr.int_custom_md.setValid();
        hdr.int_custom_md.node_id = reg_node_id.read(zero);
        hdr.int_custom_md.ingress_interface = (bit<16>) ( bit<32>) istd.ingress_port;
        hdr.int_custom_md.egress_interface = (bit<16>) (bit<32>) egress_port;
        hdr.int_custom_md.ingress_timestamp = (bit<64>) istd.ingress_timestamp;
        // hdr.int_custom_md_header.egress_timestamp = 64w0;

        /* increase packet counter by one */
        bit<32> flow_packet_count = reg_flow_packet_count.read(flow_id);
        flow_packet_count = flow_packet_count + 1;
        reg_flow_packet_count.write(flow_id, flow_packet_count);

        /* increase byte counter by packet.length() */
        bit<64> flow_byte_count = reg_flow_byte_count.read(flow_id);
        flow_byte_count = flow_byte_count + (bit<64>) meta.packet_length;
        reg_flow_byte_count.write(flow_id, flow_byte_count);

        /* add counter data to the node metadata header */
        hdr.int_custom_md.flow_byte_count = flow_byte_count;
        hdr.int_custom_md.flow_packet_count = flow_packet_count;

        hdr.ipv4.totallen = hdr.ipv4.totallen + 36;
        hdr.udp.length = hdr.udp.length + 36;
    }

    action forward_normal(PortId_t egress_port, EthernetAddress dstAddr){   
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        
        /* set the egress interface */
        send_to_port(ostd, egress_port);
    }

    action forward_source(PortId_t egress_port, EthernetAddress dstAddr, bit<8> flow_id){
        forward_normal(egress_port, dstAddr);

        hdr.int_custom_shim.setValid();
        hdr.int_custom_shim.original_dscp = hdr.ipv4.dscp;
        hdr.ipv4.dscp = DSCP_INT;
        hdr.int_custom_shim.reserved = 0;
        hdr.int_custom_shim.int_total_words = 8w9;
        hdr.int_custom_shim.remaining_int_hops = 8w2;
        hdr.int_custom_shim.flow_id = flow_id;

        hdr.ipv4.totallen = hdr.ipv4.totallen + 4;
        hdr.udp.length = hdr.udp.length + 4;

        add_int_metadata(egress_port, flow_id);
    }
    
    action forward_transit(PortId_t egress_port, EthernetAddress dstAddr, bit<8> flow_id){
        forward_normal(egress_port, dstAddr);

        hdr.int_custom_shim.int_total_words = hdr.int_custom_shim.int_total_words + 8w9;
        hdr.int_custom_shim.remaining_int_hops = hdr.int_custom_shim.remaining_int_hops - 1;

        add_int_metadata(egress_port, flow_id);
    }

    table tbl_forward{
        key = {
            // hdr.int_custom_shim.isValid() : exact;
            hdr.udp.srcPort     : exact;
            hdr.ipv4.dstAddr    : lpm;
            // hdr.ipv4.dstAddr    : lpm;
            // hdr.udp.srcPort     : exact;
        }
        actions = { NoAction; forward_normal; forward_source; forward_transit; }
    }

    apply {
        tbl_forward.apply();
    }

}  // end of ingress


#endif // __INGRESS__