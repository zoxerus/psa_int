#ifndef __DEFINES__
#define __DEFINES__

#include <core.p4>
#include <psa.p4>

#define ETH_TYPE_IPV4 16w2048
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define DSCP_INT 6w23

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;
typedef bit<16>  L4Port;

typedef bit<32>  NodeID;
typedef bit<16>  L1InterfaceID;
typedef bit<32>  HopLatency;
typedef bit<64>  Timestamp;
typedef bit<8>   QueueID;
typedef bit<24>  QueueOccupancy;
typedef bit<32>  L2InterfaceID;
typedef bit<32>  InterfaceTxUtilization;
typedef bit<8>   BufferID;
typedef bit<24>  BufferOccupancy;
typedef bit<32>  ChecksumComplement;


struct metadata {
    /*
    variable for storing the length of the telemetry stack 
    including int_md_header excluding the shim header.
    */
    // bit<16> intShimLength;
    // bool isTrackedFlow;
    bit<1> isSink;
    // bool isSource;
    // bool isTransit;
    // bit<1> isSink;
    // bool isClone;
    // bit<1> intSink;
    // bit<16> egress_port;
    // bit<32> node_id;
    // bit<64> ingress_timestamp;
    // bit<16> new_bytes;
    // bit<8>  new_words;
    // bit<8>  int_shim_len;
    bit<32> packet_length;
}



struct empty_t {}

#endif // __DEFINES__