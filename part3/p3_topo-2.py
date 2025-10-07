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

    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Add OVS switches s1..s6 with DPIDs 1..6\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid=hex_dpid(1), failMode='standalone')
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid=hex_dpid(2), failMode='standalone')
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid=hex_dpid(3), failMode='standalone')
    s4 = net.addSwitch('s4', cls=OVSSwitch, dpid=hex_dpid(4), failMode='standalone')
    s5 = net.addSwitch('s5', cls=OVSSwitch, dpid=hex_dpid(5), failMode='standalone')
    s6 = net.addSwitch('s6', cls=OVSSwitch, dpid=hex_dpid(6), failMode='standalone')

    info('*** Add hosts\n')
    h1 = net.addHost('h1', ip='10.0.12.2/24', mac='00:00:00:00:01:02')
    h2 = net.addHost('h2', ip='10.0.67.2/24', mac='00:00:00:00:06:02')

    info('*** Host <-> switch links (fixed names)\n')
    net.addLink(h1, s1, intfName1='h1-eth1', intfName2='s1-eth1')  # 10.0.12.0/24
    net.addLink(h2, s6, intfName1='h2-eth1', intfName2='s6-eth3')  # 10.0.67.0/24

    info('*** Inter-switch ring links (fixed names)\n')
    net.addLink(s1, s2, intfName1='s1-eth2', intfName2='s2-eth1')  # 10.0.13.0/24
    net.addLink(s2, s3, intfName1='s2-eth2', intfName2='s3-eth1')  # 10.0.23.0/24
    net.addLink(s3, s6, intfName1='s3-eth2', intfName2='s6-eth1')  # 10.0.36.0/24
    net.addLink(s6, s5, intfName1='s6-eth2', intfName2='s5-eth2')  # 10.0.56.0/24
    net.addLink(s5, s4, intfName1='s5-eth1', intfName2='s4-eth2')  # 10.0.45.0/24
    net.addLink(s4, s1, intfName1='s4-eth1', intfName2='s1-eth3')  # 10.0.14.0/24

    info('*** Build & start\n')
    net.build()
    net.start()

    info('*** Configure hosts: IP/MAC + default routes\n')
    h1.cmd('ip addr flush dev h1-eth1')
    h1.cmd('ip addr add 10.0.12.2/24 dev h1-eth1')
    h1.cmd('ip link set h1-eth1 address 00:00:00:00:01:02 up')
    h1.cmd('ip route add default via 10.0.12.1 dev h1-eth1')

    h2.cmd('ip addr flush dev h2-eth1')
    h2.cmd('ip addr add 10.0.67.2/24 dev h2-eth1')
    h2.cmd('ip link set h2-eth1 address 00:00:00:00:06:02 up')
    h2.cmd('ip route add default via 10.0.67.1 dev h2-eth1')

    info('*** Assign gateway IPs/MACs on host-facing switch ports\n')
    set_if(s1, 's1-eth1', ip_cidr='10.0.12.1/24', mac='00:00:00:00:01:01')  # GW for h1
    set_if(s6, 's6-eth3', ip_cidr='10.0.67.1/24', mac='00:00:00:00:06:03')  # GW for h2

    info('*** Assign IPs/MACs on ALL inter-switch links (per config)\n')
    # s1 <-> s2 (10.0.13.0/24)
    set_if(s1, 's1-eth2', ip_cidr='10.0.13.1/24', mac='00:00:00:00:01:02')
    set_if(s2, 's2-eth1', ip_cidr='10.0.13.2/24', mac='00:00:00:00:02:01')

    # s2 <-> s3 (10.0.23.0/24)
    set_if(s2, 's2-eth2', ip_cidr='10.0.23.1/24', mac='00:00:00:00:02:02')
    set_if(s3, 's3-eth1', ip_cidr='10.0.23.2/24', mac='00:00:00:00:03:01')

    # s3 <-> s6 (10.0.36.0/24)
    set_if(s3, 's3-eth2', ip_cidr='10.0.36.1/24', mac='00:00:00:00:03:02')
    set_if(s6, 's6-eth1', ip_cidr='10.0.36.2/24', mac='00:00:00:00:06:01')

    # s6 <-> s5 (10.0.56.0/24)
    set_if(s6, 's6-eth2', ip_cidr='10.0.56.2/24', mac='00:00:00:00:06:02')
    set_if(s5, 's5-eth2', ip_cidr='10.0.56.1/24', mac='00:00:00:00:05:02')

    # s5 <-> s4 (10.0.45.0/24)
    set_if(s5, 's5-eth1', ip_cidr='10.0.45.2/24', mac='00:00:00:00:05:01')
    set_if(s4, 's4-eth2', ip_cidr='10.0.45.1/24', mac='00:00:00:00:04:02')

    # s4 <-> s1 (10.0.14.0/24)
    set_if(s4, 's4-eth1', ip_cidr='10.0.14.2/24', mac='00:00:00:00:04:01')
    set_if(s1, 's1-eth3', ip_cidr='10.0.14.1/24', mac='00:00:00:00:01:03')

    info('*** Notes:\n')
    info(' - IPs/MACs are bound to OVS port devices so they will ARP/reply to ICMP.\n')
    info(' - OVS will NOT route between these subnets by itself.\n')
    info('   Use a controller with L3 logic (e.g., Ryu L3) or switch to LinuxRouter/FRR.\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build()
