#include <netinet/in.h>
#include <pcap.h>

#include <signal.h>
#include <limits.h>


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

struct sniff_udp {
    u_short th_sport;
    u_short th_dport;
    u_short th_len;
    u_short th_sum;
};

struct sniff_int {
    u_char     node_id1[4];
    u_char     latency1[4];
    u_char     node_id2[4];
    u_char     latency2[4];
    u_char     node_id3[4];
    u_char     latency3[4]; 
};


int num_packets = 0;

pcap_t *handle;
struct pcap_pkthdr header;
const u_char *packet;
const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_udp *udp; /* The TCP header */
const struct sniff_int *int_md;
const char *payload; /* Packet payload */

double min_lc = UINT_MAX;
double max_lc = 0;
double avg_lc = 0;

void handlePacket(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet){
    num_packets +=1;

    // printf("Jacked a packet with length of [%d]\n", header->len);

    // printf("Parsing Ethernet header\n");

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);


    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + 20 );
    int_md = (struct sniff_int*)(packet + SIZE_ETHERNET + 44);

    /* convert latencies to the big endian format */
    u_int lc1 = int_md->latency1[3] + (int_md->latency1[2] << 8) + (int_md->latency1[1] << 16) + (int_md->latency1[0] << 24);
    u_int lc2 = int_md->latency2[3] + (int_md->latency2[2] << 8) + (int_md->latency2[1] << 16) + (int_md->latency2[0] << 24);
    u_int lc3 = int_md->latency3[3] + (int_md->latency3[2] << 8) + (int_md->latency3[1] << 16) + (int_md->latency3[0] << 24);

    double latency = lc1 + lc2 + lc3;

    avg_lc = avg_lc + (latency - avg_lc)/num_packets;

    if (latency < min_lc) { 
        min_lc = latency; 
    } else if (latency > max_lc ) {
        max_lc = latency;
    }
    
    /* print node ids in hex*/
    // printf("Node 1 Id: %02X.%02X.%02X.%02X \n", int_md->node_id1[0], int_md->node_id1[1], int_md->node_id1[2], int_md->node_id1[3]  );
    // printf("Node 1 lc: %d\n", lc1);

    // printf("Node 2 Id: %02X.%02X.%02X.%02X \n",int_md->node_id2[0], int_md->node_id2[1], int_md->node_id2[2], int_md->node_id2[3]  );
    // printf("Node 2 lc: %d\n", lc2);

    // printf("Node 3 Id: %02X.%02X.%02X.%02X \n", int_md->node_id3[0], int_md->node_id3[1], int_md->node_id3[2], int_md->node_id3[3]  );
    // printf("Node 3 lc: %d\n", lc3);

    // printf("# Packets: %u\n", num_packets);
}




void sigint_handler(int signum) { //Handler for SIGINT
    pcap_breakloop(handle);


//    //Reset handler to catch SIGINT next time.
//    signal(SIGINT, sigint_handler);
//    printf("Cannot be stopped using Ctrl+C ");
//    fflush(stdout);
}


int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);
    printf( "sizeof int: %ld\n", sizeof(int) );
    printf( "sizeof u_int: %ld\n", sizeof(u_int) );


    printf("Launching Packet Capture");

    char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];
    int BUFSIZE = 1024;

    struct bpf_program fp;
    char filter_exp[] = "port 12345";
    bpf_u_int32 mask;
    bpf_u_int32 net;


    u_int size_ip;
    u_int size_tcp;


    // dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    printf("\nDevice: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    // packet = pcap_next(handle, &header);

    pcap_loop(handle, -1, handlePacket, NULL);

    printf("\n# packets: %d\nmin_lc: %.0f us\nmax_lc: %.0f us\navg_lc: %.0f us", num_packets, min_lc, max_lc, avg_lc);

    printf("\nended\n");
    
    return(0);
}
