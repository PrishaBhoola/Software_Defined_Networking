#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def hex_dpid(n: int) -> str:
    return f"{int(n):016x}"

def set_if(node, ifname, ip_cidr=None, mac=None):
    node.cmd(f'ip link set dev {ifname} down')
    node.cmd(f'ip addr flush dev {ifname}')
    if mac:
        node.cmd(f'ip link set dev {ifname} address {mac}')
    if ip_cidr:
        node.cmd(f'ip addr add {ip_cidr} dev {ifname}')
    node.cmd(f'ip link set dev {ifname} up')

def build():
    net = Mininet(
        controller=None, build=False, link=TCLink,
        autoSetMacs=False, autoStaticArp=False
    )

    # Remote controller (Ryu/others) on localhost:6633
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Add OVS switches s1..s6 with fixed DPIDs\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid=hex_dpid(1), failMode='standalone')
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid=hex_dpid(2), failMode='standalone')
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid=hex_dpid(3), failMode='standalone')
    s4 = net.addSwitch('s4', cls=OVSSwitch, dpid=hex_dpid(4), failMode='standalone')
    s5 = net.addSwitch('s5', cls=OVSSwitch, dpid=hex_dpid(5), failMode='standalone')
    s6 = net.addSwitch('s6', cls=OVSSwitch, dpid=hex_dpid(6), failMode='standalone')

    info('*** Add hosts (unique MACs)\n')
    h1 = net.addHost('h1', ip='10.0.12.2/24', mac='00:00:00:00:01:02')
    h2 = net.addHost('h2', ip='10.0.67.2/24', mac='00:00:00:00:06:02')

    info('*** Host <-> switch links (pin ports so numbering is stable)\n')
    # s1: port1=h1, port2->s2, port3->s4
    net.addLink(h1, s1, intfName1='h1-eth1', intfName2='s1-eth1', port1=1, port2=1)

    # s6: port1<-s3, port2<-s5, port3=h2
    net.addLink(h2, s6, intfName1='h2-eth1', intfName2='s6-eth3', port1=1, port2=3)

    info('*** Inter-switch ring links (all ports pinned)\n')
    # s1 <-> s2 (10.0.13.0/24)
    net.addLink(s1, s2, intfName1='s1-eth2', intfName2='s2-eth1', port1=2, port2=1)
    # s2 <-> s3 (10.0.23.0/24)
    net.addLink(s2, s3, intfName1='s2-eth2', intfName2='s3-eth1', port1=2, port2=1)
    # s3 <-> s6 (10.0.36.0/24)
    net.addLink(s3, s6, intfName1='s3-eth2', intfName2='s6-eth1', port1=2, port2=1)
    # s6 <-> s5 (10.0.56.0/24)
    net.addLink(s6, s5, intfName1='s6-eth2', intfName2='s5-eth2', port1=2, port2=2)
    # s5 <-> s4 (10.0.45.0/24)
    net.addLink(s5, s4, intfName1='s5-eth1', intfName2='s4-eth2', port1=1, port2=2)
    # s4 <-> s1 (10.0.14.0/24)
    net.addLink(s4, s1, intfName1='s4-eth1', intfName2='s1-eth3', port1=1, port2=3)

    info('*** Build & start\n')
    net.build()
    net.start()

    info('*** Configure hosts + default routes\n')
    h1.cmd('ip addr flush dev h1-eth1')
    h1.cmd('ip addr add 10.0.12.2/24 dev h1-eth1')
    h1.cmd('ip link set h1-eth1 address 00:00:00:00:01:02 up')
    h1.cmd('ip route add default via 10.0.12.1 dev h1-eth1')

    h2.cmd('ip addr flush dev h2-eth1')
    h2.cmd('ip addr add 10.0.67.2/24 dev h2-eth1')
    h2.cmd('ip link set h2-eth1 address 00:00:00:00:06:02 up')
    h2.cmd('ip route add default via 10.0.67.1 dev h2-eth1')

    info('*** Assign gateway IPs on host-facing switch ports (unique MACs)\n')
    # Gateways (stable MACs for ARP)
    set_if(s1, 's1-eth1', ip_cidr='10.0.12.1/24', mac='00:00:00:00:01:01')  # GW for h1
    set_if(s6, 's6-eth3', ip_cidr='10.0.67.1/24', mac='00:00:00:00:06:03')  # GW for h2

    info('*** Assign IPs on inter-switch links (let kernel pick MACs to avoid duplicates)\n')
    # s1 <-> s2 (10.0.13.0/24)
    set_if(s1, 's1-eth2', ip_cidr='10.0.13.1/24')
    set_if(s2, 's2-eth1', ip_cidr='10.0.13.2/24')

    # s2 <-> s3 (10.0.23.0/24)
    set_if(s2, 's2-eth2', ip_cidr='10.0.23.1/24')
    set_if(s3, 's3-eth1', ip_cidr='10.0.23.2/24')

    # s3 <-> s6 (10.0.36.0/24)
    set_if(s3, 's3-eth2', ip_cidr='10.0.36.1/24')
    set_if(s6, 's6-eth1', ip_cidr='10.0.36.2/24')

    # s6 <-> s5 (10.0.56.0/24)
    set_if(s6, 's6-eth2', ip_cidr='10.0.56.2/24')
    set_if(s5, 's5-eth2', ip_cidr='10.0.56.1/24')

    # s5 <-> s4 (10.0.45.0/24)
    set_if(s5, 's5-eth1', ip_cidr='10.0.45.2/24')
    set_if(s4, 's4-eth2', ip_cidr='10.0.45.1/24')

    # s4 <-> s1 (10.0.14.0/24)
    set_if(s4, 's4-eth1', ip_cidr='10.0.14.2/24')
    set_if(s1, 's1-eth3', ip_cidr='10.0.14.1/24')

    info('*** Notes:\n')
    info(' - Port numbers are now fixed; link order will not change them.\n')
    info(' - Gateways live on s1-eth1 (10.0.12.1) and s6-eth3 (10.0.67.1).\n')
    info(' - Use an L3 controller (e.g., Ryu) or FRR if you want real routing between subnets.\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build()
