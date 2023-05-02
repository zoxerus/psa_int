#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR



def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface
x = 0
def handle_pkt(pkt):
    global x
    telemetryPacketLengthInBytes = 8
    l = telemetryPacketLengthInBytes
    if UDP in pkt and pkt[UDP].dport == 12345:
        # pkt.show2()
        x = x + 1
        data = pkt[Raw].load

        print('\n---- Telemetry Packet: {0} ----'.format(x) )

        print('int_type:\t\t{}'.format( (data[0] >> 4) ) )
        print('next_protocol:\t\t{}'.format(( data[0] & 0b00001100) >> 2 ))
        print('reserved:\t\t{}'.format(( data[0] & 0b00000011) ))
        print('int_length:\t\t{}'.format((data[1])))
        print('udp_ip_dscp:\t\t{}'.format( (int.from_bytes(data[2:4],byteorder = "big") )))
        print('ver:\t\t\t{}'.format( (data[4] >> 4) ) )
        print('d:\t\t\t{}'.format( ( (data[4] & 0b00001000 >> 3) ) ) )
        print('e:\t\t\t{}'.format( ( (data[4] & 0b00000100 >> 2) ) ) )
        print('m:\t\t\t{}'.format( ( (data[4] & 0b00000010 >> 1) ) ) )
        print('reserved:\t\t{}'.format(( int.from_bytes( data[4:7], byteorder='big' ) & 0b000000011111111111100000) >> 5  ))
        print('hop_md_length:\t\t{}'.format( ( (data[6] & 0b00011111) ) ) )

        print('remaining_hop_count:\t{}'.format((data[7])))

        print('instruction_bitmap:\t{}'.format( int.from_bytes(data[8:10], byteorder='big' ) ))
        print('domain_sID:\t\t{}'.format( int.from_bytes(data[10:12], byteorder='big' ) ))
        print('domain_sInstruction:\t{}'.format( int.from_bytes(data[12:14], byteorder='big' ) ))
        print('domain_sFlags:\t\t{}'.format( int.from_bytes(data[14:16], byteorder='big' ) ))

        print("\n\n")
        data = data[16:]

        for i in range(3):
            # pkt.show2()
            # break
            n = l*i

            print('Node_ID:\t\t{}.{}.{}.{}'.format( data[0+n],data[1+n],data[2+n],data[3+n]))

            print('Latency:\t\t{} ms'.format( int.from_bytes(data[4+n:8+n], byteorder='big' )/1000 ))

 
            print('\n')
        print('---- end ----\n')
       # hexdump(pkt)
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth0' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
    print('\r Received: {} Packets'.format(x) )
