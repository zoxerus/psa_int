
#ifndef __EGRESS__
#define __EGRESS__

/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    // bit<64> one = 1;
    // bit<16> two = 1;
    // bit<8>  three = 1;


    // Register < bit<64>, bit<64> >(1) tstamp;
    // Register < bit<16>, bit<16> >(1) iplen;
    // Register < bit<8>, bit<8> >(1) shim_len;

    apply {
        // tstamp.write( one , hdr.umeta.ingress_timestamp );
        /* 
        Add the telemetry metadata to the packet according to the 
        instruction bitmap in the int_md header.
        */
        InsertMetadata.apply(hdr, meta, istd, ostd);
        /*
        check if the packet is cloned to the collectoer, and
        set the proper destination MAC and IP addresses.
        */



        if ( istd.packet_path == PSA_PacketPath_t.CLONE_I2E ){

            hdr.ipv4.totallen = hdr.ipv4.totallen - (bit<16>) ((hdr.int_shim.int_total_length + 1) << 2);
            // iplen.write( two, hdr.ipv4.totallen );

            // shim_len.write( three, hdr.int_shim.int_total_length);
            hdr.udp.length_ = hdr.udp.length_ - (bit<16>) ((hdr.int_shim.int_total_length + 1) << 2) ;

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
            if ( hdr.umeta.isValid() && hdr.umeta.isINTSink == 1w1 ){

                /*
                set the ethernet destination address to: 56:1E:10:00:04:10
                and IP destination address to 10.0.4.10 of the collector.
                */
                hdr.ethernet.dstAddr = 94687117444112;
                hdr.ipv4.dstAddr = 0xa00040a;

            }
        }



        hdr.umeta.setInvalid();
     }
} // end of egress


#endif // __EGRESS__