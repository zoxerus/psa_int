#ifndef __IN_PARSER__
#define __IN_PARSER__

#include "headers.p4"

/****************************************************************/

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
        // meta.int_shim_len = parsed_hdr.int_shim.int_total_length;
        transition accept;
    }
} // end of IngressParserImpl

/************************************************************************/
/************************************************************************/

/* Ingress Deparser */
control IngressDeparserImpl(packet_out buffer,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out metadata normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{

    apply {
        // Assignments to the out parameter normal_meta must be
        // guarded by this if condition:
        // if (psa_normal(istd)) {
        //     normal_meta = meta;
        // }

        /* 
        umeta carries user metadata to the egress 
        this header is then removed from the packet.
        */
        buffer.emit(hdr.umeta);

        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
        buffer.emit(hdr.udp);
        buffer.emit(hdr.int_shim);
        buffer.emit(hdr.int_md);
    }
}

#endif // __IN_PARSER__