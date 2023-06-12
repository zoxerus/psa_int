#ifndef  __OUT_PARSER__
#define __OUT_PARSER__



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

        transition select (istd.packet_path){
            PSA_PacketPath_t.CLONE_E2E : parse_clone;
            PSA_PacketPath_t.NORMAL : parse_ethernet;
            default                 : accept;
        }
    }

    state parse_clone{
        meta.isSink = 1w1;
        buffer.extract(parsed_hdr.ethernet);
        buffer.extract(parsed_hdr.ipv4);
        buffer.extract(parsed_hdr.udp);
        buffer.extract(parsed_hdr.int_custom_shim);
        buffer.extract(parsed_hdr.int_data);
        transition accept;
    }

    /* 
    parse the dummy header to get access to the user metadata,
    this header is used instead of the normal_meta due to limitations
    with the NIKSS switch.
    */
    // state parse_umeta{
    //     buffer.extract(parsed_hdr.umeta);
    //     transition select(){
    //         default : parse_ethernet;
    //     }
    // }


    state parse_ethernet {
        /* extract ethernet header */
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            ETH_TYPE_IPV4:  parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        /* extract ipv4 header */
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol){
            IP_PROTO_UDP:   parse_udp;
            default:        accept;
        }
    }

    state parse_udp {
        /* extract udp header */
        buffer.extract(parsed_hdr.udp);
        transition select(parsed_hdr.ipv4.dscp){
            DSCP_INT: parse_int;
            default: accept;
        }
    }
    state parse_int {
        /* extract the shim and int metadata headers */
        buffer.extract(parsed_hdr.int_custom_shim);
        buffer.extract(parsed_hdr.int_custom_md);
        /*
        determine if this node is a sink from the remaining hop count in the
        INT MD header, if the remaining is one then this is the last node
        and must play the sink role. here we use this method of determining
        the sink role, because there is no way with NIKSS switch to carry
        metadata from ingress to egress for the cloned packets not even with 
        the dummy header.
        */
        if(parsed_hdr.int_custom_shim.remaining_int_hops == 0){
            meta.isSink = 1w1;
        }
        transition accept;


        // transition select(parsed_hdr.int_custom_shim.remaining_int_hops){
        //     0 : parse_int_sink;
        //     default : accept;
        // }
    }

    // state parse_int_sink {
    //     meta.isSink = 1w1;
    //     buffer.extract(parsed_hdr.int_data);
    //     transition accept;

    // }

} // end of EgressParserImpl




control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{

    apply {
        /* first emit the normal packet headers */
        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
        buffer.emit(hdr.udp);
        buffer.emit(hdr.int_custom_shim);
        buffer.emit(hdr.int_custom_md);


        /* for INT packets emit the shim and int_md headers */
        // buffer.emit(hdr.int_shim);
        // buffer.emit(hdr.int_md);
        /* 
        emit any metadata collected by the node based on the 
        instruction bitmap
        */
        // buffer.emit(hdr.int_node_id);
        // buffer.emit(hdr.int_l1_interfaces);
        // buffer.emit(hdr.int_hop_latency);
        // buffer.emit(hdr.int_queue_info);
        // buffer.emit(hdr.int_ingress_timestamp);
        // buffer.emit(hdr.int_egress_timestamp);
        // buffer.emit(hdr.int_l2_interfaces);
        // buffer.emit(hdr.int_egress_tx);
        // buffer.emit(hdr.int_buffer_info);
        // buffer.emit(hdr.int_checksum);
        // /* emit the metadata stack from upstream nodes in the network */
        // buffer.emit(hdr.int_data);
    }
}


#endif // __OUT_PARSER__