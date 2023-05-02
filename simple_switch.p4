#include "./include/md_insert.p4"
#include "./include/ingress_parsing.p4"
#include "./include/egress_parsing.p4"
#include "./include/ingress.p4"
#include "./include/egress.p4"







IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;



EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;


PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
