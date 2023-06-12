
#ifndef __EGRESS__
#define __EGRESS__

/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{

    Register<bit<64>, bit<32>>(32w6) reg_flow_byte_count;
    Register<bit<32>, bit<32>>(32w6) reg_flow_packet_count;
    Register<bit<64>, bit<32>>(32w255) reg_port_byte_count;
    Register<bit<32>, bit<32>>(32w255) reg_port_packet_count;

    bit<32> zero;

    action process_transit(){

        bit<32> flow_id = (bit<32>) hdr.int_custom_shim.flow_id;
        hdr.int_custom_md.egress_timestamp = (bit<64>) istd.egress_timestamp;

        /* increase packet counter by one */
        bit<32> flow_packet_count = reg_flow_packet_count.read(flow_id);
        flow_packet_count = flow_packet_count + 1;
        reg_flow_packet_count.write(flow_id, flow_packet_count);

        /* increase byte counter by packet.length() */
        bit<64> flow_byte_count = reg_flow_byte_count.read(flow_id);
        flow_byte_count = flow_byte_count + (bit<64>) meta.packet_length;
        reg_flow_byte_count.write(flow_id, flow_byte_count);

        hdr.int_custom_md.out_port_byte_count = reg_port_byte_count.read( zero);
        hdr.int_custom_md.out_port_packet_count = reg_port_packet_count.read( zero);
        hdr.int_custom_md.out_port_flow_byte_count = flow_byte_count;
        hdr.int_custom_md.out_port_flow_packet_count = flow_packet_count;

    }

    action process_sink(CloneSessionId_t session_id){
        ostd.clone = true;
        ostd.clone_session_id = session_id;
        process_transit();
    }

    action process_clone(){
        hdr.ipv4.dscp = hdr.int_custom_shim.original_dscp;
        hdr.int_custom_shim.setInvalid();
        hdr.int_custom_md.setInvalid();
        hdr.ipv4.totallen = hdr.ipv4.totallen - MD_HDR_LEN_BYTES - MD_HDR_LEN_BYTES - MD_HDR_LEN_BYTES - SHIM_HDR_LEN_BYTES;
        hdr.udp.length = hdr.udp.length - MD_HDR_LEN_BYTES - MD_HDR_LEN_BYTES - MD_HDR_LEN_BYTES - SHIM_HDR_LEN_BYTES;
    }

    table tbl_packet_fate{
        key = {
            meta.isSink      : exact;
            istd.packet_path : exact;
        }
        actions = {NoAction; process_sink; process_transit; process_clone;}
        const entries = {
            (1, PSA_PacketPath_t.NORMAL) : process_sink( (CloneSessionId_t) 16w500);
            (1, PSA_PacketPath_t.CLONE_E2E) : process_clone();
            (0, PSA_PacketPath_t.NORMAL)    : process_transit();
        }
    }

    apply {
        zero = 0;
        /* update port counters */
        bit<64> byte_count = reg_port_byte_count.read( zero);
        byte_count = byte_count + (bit<64>) meta.packet_length;
        reg_port_byte_count.write( zero, byte_count);

        bit<32> packet_count = reg_port_packet_count.read( zero );
        packet_count = packet_count + 1;
        reg_port_packet_count.write( zero, packet_count);

        /* apply packet fate*/
        tbl_packet_fate.apply();
     }
} // end of egress


#endif // __EGRESS__