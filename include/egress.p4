
#ifndef __EGRESS__
#define __EGRESS__

/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{

    action process_sink(CloneSessionId_t session_id){
        ostd.clone = true;
        ostd.clone_session_id = session_id;
        hdr.int_custom_md.egress_timestamp = (bit<64>) istd.egress_timestamp;

    }

    action process_transit(){
        hdr.int_custom_md.egress_timestamp = (bit<64>) istd.egress_timestamp;
    }

    action process_clone(){
        hdr.ipv4.dscp = hdr.int_custom_shim.original_dscp;
        hdr.int_custom_shim.setInvalid();
        hdr.int_custom_md.setInvalid();
        hdr.ipv4.totallen = hdr.ipv4.totallen - 112;
        hdr.udp.length = hdr.udp.length - 112;
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
        tbl_packet_fate.apply();
     }
} // end of egress


#endif // __EGRESS__