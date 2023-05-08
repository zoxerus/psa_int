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
        /* extract ethernet header */
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            ETH_TYPE_IPV4:  parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        /* extract IPv4 header */
        buffer.extract(parsed_hdr.ipv4);
        transition select(parsed_hdr.ipv4.protocol){
            IP_PROTO_UDP:   parse_udp;
            default:        accept;
        }
    }

    state parse_udp {
        /* extract UDP header */
        buffer.extract(parsed_hdr.udp);
        /* determine if this packet is carrying INT header from the DSCP field */
        transition select(parsed_hdr.ipv4.dscp){
            DSCP_INT: parse_int;  // DSCP indicates if the packet is carrying INT
            default: accept;
        }
    }

    state parse_int {
        /* extract the shim header and INT metadata header */
        buffer.extract(parsed_hdr.int_shim);
        buffer.extract(parsed_hdr.int_md);
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
        /* 
        umeta is adummy header that carries user metadata to the egress 
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