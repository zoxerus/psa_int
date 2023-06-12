#!/usr/bin/env python3

import socket

from lib.nikss_mn import P4Host, NIKSSSwitch

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import SingleSwitchTopo

from time import sleep

class MyCustomTopo(Topo):

    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        s1 = self.addSwitch('s1',
                                bpf_path="simple_switch.o",
                                enable_tracing = True)
        s2 = self.addSwitch('s2',
                                bpf_path="simple_switch.o",
                                enable_tracing = True)
        s3 = self.addSwitch('s3',
                                bpf_path="simple_switch.o",
                                enable_tracing = True)
        h1 = self.addHost('h1',
                            ip = "10.0.1.10/24",
                            mac = '56:1E:10:00:01:10',
                            commands = ["route add default gw 10.0.1.1 dev eth0",
                            "arp -i eth0 -s 10.0.1.1 56:1E:10:00:01:01"])
        
        h2 = self.addHost('h2',
                            ip = '10.0.2.10/24',
                            mac = '56:1E:10:00:02:10',
                            commands = ["route add default gw 10.0.2.1 dev eth0",
                            "arp -i eth0 -s 10.0.2.1 56:1E:10:00:02:01"])
        
        h3 = self.addHost('h3',
                            ip = "10.0.3.10/24",
                            mac = '56:1E:10:00:03:10',
                            commands = ["route add default gw 10.0.3.1 dev eth0",
                            "arp -i eth0 -s 10.0.3.1 56:1E:10:00:03:01"])
        
        h4 = self.addHost('h4',
                            ip = "10.0.4.10/24",
                            mac = '56:1E:10:00:04:10',
                            commands = ["route add default gw 10.0.4.1 dev eth0",
                            "arp -i eth0 -s 10.0.4.1 56:1E:10:00:04:01"])
            

        self.addLink(h2, s2 , 1, 1)
        self.addLink(h3, s3 , 1, 1)
        self.addLink(h4, s3 , 1, 2)
        self.addLink(s1, s2 , 2, 2)
        self.addLink(s2, s3 , 3, 3)
        self.addLink(h1, s1 , 1, 1)



def main():
    topo = MyCustomTopo()
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = NIKSSSwitch,
                  controller = None)
    net.start()

    sleep(1)

    h1 = net.get('h1')
    # h1.setARP("10.0.1.1", "00:04:00:00:00:01")

    h2 = net.get('h2')
    # h2.setARP("10.0.2.1", "00:04:00:00:00:02")

    h3 = net.get('h3')
    # h3.setARP("10.0.3.1", "00:04:00:00:00:03")

    h4 = net.get('h4')

    s1 = net.get('s1')
    s2 = net.get('s2')
    s3 = net.get('s3')

    s1.setMAC('56:1E:10:00:10:01', intf = 's1-eth1')
    s1.setMAC('56:1E:10:00:12:01', intf = 's1-eth2')

    s1.setIP('10.0.1.1/24', intf = 's1-eth1')
    s1.setIP('10.0.12.1/24', intf = 's1-eth2')

    s2.setMAC('56:1E:10:00:20:01', intf = 's2-eth1')
    s2.setMAC('56:1E:10:00:12:02', intf = 's2-eth2')
    s2.setMAC('56:1E:10:00:23:01', intf = 's2-eth3')

    s2.setIP('10.0.2.1/24', intf = 's2-eth1')
    s2.setIP('10.0.12.2/24', intf = 's2-eth2')
    s2.setIP('10.0.23.1/24', intf = 's2-eth3')

    s3.setMAC('56:1E:10:00:30:01', intf = 's3-eth1')
    s3.setMAC('56:1E:10:00:40:01', intf = 's3-eth2')
    s3.setMAC('56:1E:10:00:23:02', intf = 's3-eth3')

    s3.setIP('10.0.3.1/24', intf = 's3-eth1')
    s3.setIP('10.0.4.1/24', intf = 's3-eth2')
    s3.setIP('10.0.23.2/24', intf = 's3-eth3')


    h1 = net.get('h1')
    h1.setARP('10.0.1.1', '56:1E:10:00:10:01')
    h1.setDefaultRoute("dev eth0 via %s" % '10.0.1.1')
    h1.describe()

    h2 = net.get('h2')
    h2.setARP('10.0.2.1', '56:1E:10:00:20:01')
    h2.setDefaultRoute("dev eth0 via %s" % '10.0.2.1')
    h2.describe()

    h3 = net.get('h3')
    h3.setARP('10.0.3.1', '56:1E:10:00:30:01')
    h3.setDefaultRoute("dev eth0 via %s" % '10.0.3.1')
    h3.describe()

    h4 = net.get('h4')
    h4.setARP('10.0.4.1', '56:1E:10:00:40:01')
    h4.setDefaultRoute("dev eth0 via %s" % '10.0.4.1')
    h4.describe()

    print("s1-eth1: ", socket.if_nametoindex("s1-eth1"))
    print("s2-eth1: ", socket.if_nametoindex("s2-eth1"))
    print("s3-eth1: ", socket.if_nametoindex("s3-eth1"))

    # Entries for S1 ingress_tbl_forward
    # s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h1.IP(), socket.if_nametoindex("s1-eth1"),
    #                                                                                             "56:1E:10:00:10:01", "56:1E:10:00:01:10"))
    # s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h2.IP(), socket.if_nametoindex("s1-eth2"),
    #                                                                                             "56:1E:10:00:12:01", "56:1E:10:00:12:02"))
    # s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h3.IP(), socket.if_nametoindex("s1-eth2"),
    #                                                                                             "56:1E:10:00:12:01", "56:1E:10:00:12:02"))
    # # Entries for S1 tbl_role_source
    # s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_role_source action id 1 key 0 {0} {1} {2} data {3} {4} {5} {6} {7} {8}".format(h1.IP(),
    #                         "11111", socket.if_nametoindex("s1-eth1"), 
    #                         "3", "3", "14", "0", "0", "0"))
    
    # # Entries for S1 tbl_role_source
    # s1.cmd("nikss-ctl table add pipe 0 egress_InsertMetadata_tb_int_insert action id 1 key 1 data 1.1.1.1")
    


    # # Entries for S2
    # s2.cmd("nikss-ctl table add pipe 1 ingress_tbl_fwd action id 1 key {} data {} {} {} ".format(
    #     h1.IP(), socket.if_nametoindex("s2-eth2"), "56:1E:10:00:12:02", "56:1E:10:00:12:01"))
    
    # s2.cmd("nikss-ctl table add pipe 1 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(
    #     h2.IP(), socket.if_nametoindex("s2-eth1"), "56:1E:10:00:20:01", "56:1E:10:00:02:10"))

    # s2.cmd("nikss-ctl table add pipe 1 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(
    #     h3.IP(), socket.if_nametoindex("s2-eth3"), "56:1E:10:00:23:01", "56:1E:10:00:23:02"))
    
    # s2.cmd("nikss-ctl table add pipe 1 egress_InsertMetadata_tb_int_insert action id 1 key 1 data 2.2.2.2")
    
    # # Entries for S3 Source Telemetry
    # # s3.cmd("""nikss-ctl table add pipe 0 ingress_tbl_role_source 
    # #     action id 1 key {0} {1} {2} data {3} {4} {5} {6} {7} {8}""".format(h2.IP(),
    # #                         "11111", socket.if_nametoindex("s2-eth1"), 
    # #                         "2", "4", "14", "0", "0", "0"))  

    # # Entries for S3
    # s3.cmd("nikss-ctl table add pipe 2 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h1.IP(), socket.if_nametoindex("s3-eth3"),
    #                                                                                             "56:1E:10:00:23:02", "56:1E:10:00:23:01"))
    # s3.cmd("nikss-ctl table add pipe 2 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h2.IP(), socket.if_nametoindex("s3-eth3"),
    #                                                                                             "56:1E:10:00:23:02", "56:1E:10:00:23:01"))
    # s3.cmd("nikss-ctl table add pipe 2 ingress_tbl_fwd action id 1 key {} data {} {} {}".format(h3.IP(), socket.if_nametoindex("s3-eth1"),
    #                                                                                             "56:1E:10:00:30:01", "56:1E:10:00:03:10"))
    
    # s3.cmd("nikss-ctl table add pipe 2 egress_InsertMetadata_tb_int_insert action id 1 key 1 data 3.3.3.3")

    # # Entries for S3 Source Telemetry
    # # s3.cmd("""nikss-ctl table add pipe 0 ingress_tbl_role_source 
    # #     action id 1 key {0} {1} {2} data {3} {4} {5} {6} {7} {8}""".format(h3.IP(),
    # #                         "11111", socket.if_nametoindex("s3-eth1"), 
    # #                         "2", "4", "14", "0", "0", "0"))
    

    # # Entries for S3 Sink Telemetry
    # s3.cmd("nikss-ctl clone-session create pipe 2 id 128")
    # s3.cmd("nikss-ctl clone-session add-member pipe 2 id 128 egress-port {} instance 0".format(socket.if_nametoindex("s3-eth1") ))

    # s3.cmd("nikss-ctl table add pipe 2 ingress_tbl_role_sink action id 1 key 1 {0} {1} {2} data {3} {4}".format(h3.IP(),
    #                         "11111", socket.if_nametoindex("s3-eth1"), "128", socket.if_nametoindex("s3-eth2") ))   

    s1.cmd('nikss-ctl register set pipe 0 ingress_reg_node_id index 0 value 0xaaaaaaaa ')
    s2.cmd('nikss-ctl register set pipe 1 ingress_reg_node_id index 0 value 0xbbbbbbbb ')
    s3.cmd('nikss-ctl register set pipe 2 ingress_reg_node_id index 0 value 0xcccccccc ')

    s1.cmd(
    "nikss-ctl table add pipe 0 ingress_tbl_forward action id 2 key 44001 {}/24 data {} {} {}".format(
        h3.IP(), socket.if_nametoindex("s1-eth2"), "56:1E:10:00:01:10", 1))
    s1.cmd(
    "nikss-ctl table add pipe 0 ingress_tbl_forward action id 2 key 44002 {}/24 data {} {} {}".format(
        h3.IP(), socket.if_nametoindex("s1-eth2"), "56:1E:10:00:01:10", 2))
    
    s1.cmd(
    "nikss-ctl table add pipe 0 ingress_tbl_forward action id 1 key 44000 {}/24 data {} {}".format(
        h3.IP(), socket.if_nametoindex("s1-eth2"), "56:1E:10:00:01:10"))
    
    s2.cmd(
    "nikss-ctl table add pipe 1 ingress_tbl_forward action id 3 key 44001 {}/24 data {} {} {}".format(
        h3.IP(), socket.if_nametoindex("s2-eth3"), "56:1E:10:00:23:02", 1))
    s2.cmd(
    "nikss-ctl table add pipe 1 ingress_tbl_forward action id 3 key 44002 {}/24 data {} {} {}".format(
        h3.IP(), socket.if_nametoindex("s2-eth3"), "56:1E:10:00:23:02", 2))
    s2.cmd(
    "nikss-ctl table add pipe 1 ingress_tbl_forward action id 1 key 44000 {}/24 data {} {}".format(
        h3.IP(), socket.if_nametoindex("s2-eth3"), "56:1E:10:00:23:02"))
    
    s3.cmd(
    "nikss-ctl table add pipe 2 ingress_tbl_forward action id 1 key 44000 {}/24 data {} {}".format(
        h3.IP(), socket.if_nametoindex("s3-eth1"), "56:1E:10:00:03:10"))    
    s3.cmd(
    "nikss-ctl table add pipe 2 ingress_tbl_forward action id 3 key 44001 {}/24 data {} {} {}".format(
        h3.IP(), socket.if_nametoindex("s3-eth2"), "56:1E:10:00:03:10", 1))

    s3.cmd("nikss-ctl clone-session create pipe 2 id 500")
    s3.cmd("nikss-ctl clone-session add-member pipe 2 id 500 egress-port {} instance 0".format(socket.if_nametoindex("s3-eth1") ))

    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
