
#ifndef __EGRESS__
#define __EGRESS__

/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{

    apply {
        /* 
        Add the telemetry metadata to the packet according to the 
        instruction bitmap in the int_md header.
        */
        InsertMetadata.apply(hdr, meta, istd, ostd);
        /*
        in this application we are sending the cloned packet to the original
        destination, while we are changing the destination of the original packet
        to be sent to the collector.
        */
        if ( istd.packet_path == PSA_PacketPath_t.CLONE_I2E ){
            /* set the lengths to exclude the added shim, int_md, and md_stack */
            hdr.ipv4.totallen = hdr.ipv4.totallen - (bit<16>) ((hdr.int_shim.int_total_length + 1) << 2);
            hdr.udp.length_ = hdr.udp.length_ - (bit<16>) ((hdr.int_shim.int_total_length + 1) << 2) ;

            /* invalidate all the irrelevant headers */
            hdr.int_shim.setInvalid();
            hdr.int_md.setInvalid();
            hdr.int_node_id.setInvalid();
            hdr.int_l1_interfaces.setInvalid();
            hdr.int_hop_latency.setInvalid();
            hdr.int_queue_info.setInvalid();
            hdr.int_ingress_timestamp.setInvalid();
            hdr.int_egress_timestamp.setInvalid();
            hdr.int_l2_interfaces.setInvalid();
            hdr.int_egress_tx.setInvalid();
            hdr.int_buffer_info.setInvalid();
            hdr.int_checksum.setInvalid();
            hdr.int_data.setInvalid();

        } else { 
            /* if packet is original and this node is a sink then forward it to the collector */
            if ( hdr.umeta.isValid() && hdr.umeta.isINTSink == 1w1 ){

                /*
                set the ethernet destination address to: 56:1E:10:00:04:10
                and IP destination address to 10.0.4.10 of the collector.
                */
                hdr.ethernet.dstAddr = 94687117444112;
                hdr.ipv4.dstAddr = 0xa00040a;
            }
        }
        /* invalidate the umeta header, this probably is suncessary */
        hdr.umeta.setInvalid();
     }
} // end of egress


#endif // __EGRESS__