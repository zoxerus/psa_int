#ifndef  __OUT_PARSER__
#define __OUT_PARSER__



/* The Egress Parser */
parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in metadata normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{   



    state start {

        transition select (istd.packet_path){
            PSA_PacketPath_t.CLONE_I2E : parse_ethernet;
            PSA_PacketPath_t.NORMAL : parse_umeta;
            default                 : accept;
        }
    }

    state parse_umeta{
        buffer.extract(parsed_hdr.umeta);
        transition select(){
            default : parse_ethernet;
        }
    }


    state parse_ethernet {
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
        transition select(parsed_hdr.int_md.remaining_hop_count){
            1 : parse_int_sink;
            default : accept;
        }
    }

    state parse_int_sink {
        buffer.extract(parsed_hdr.int_data);
        // buffer.extract(parsed_hdr.int_shim);
        // buffer.extract(parsed_hdr.int_md);
        // /* int_total_length doesn't include the shim header (1 word) */
        // // meta.int_shim_len = parsed_hdr.int_shim.int_total_length;
        // transition select(parsed_hdr.umeta.isINTSink){
        //     1w1 : parse_int_data;
        //     default : accept; }

        transition accept;

    }

    // state parse_int_data{
    //     /* 
    //     extract the INT metadata included after the int_md header
    //     length of extraction is calculated from the int_shim_len 
    //     as it is measured in words, minus 4 which is the length of
    //     the int_md header then left-shifted by five equal to multiplying
    //     by 32 to convert from words to bits. 
    //     */
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
        buffer.emit(hdr.int_egress_timestamp);
        buffer.emit(hdr.int_l2_interfaces);
        buffer.emit(hdr.int_egress_tx);
        buffer.emit(hdr.int_buffer_info);
        buffer.emit(hdr.int_checksum);
        buffer.emit(hdr.int_data);
    }
}


#endif // __OUT_PARSER__