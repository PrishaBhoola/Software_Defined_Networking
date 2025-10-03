from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch

class CustomTopo(Topo):
    def build(self):
        # Add two switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        
        # Connect hosts to switch S1
        self.addLink(h1, s1)
        self.addLink(h2, s6)

        # Connect switches with each other
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s5)
        self.addLink(s4, s6)
        self.addLink(s5, s6)
        
def run():
    """Create the network, start it, and enter the CLI."""
    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, build=False, controller=None,
              autoSetMacs=True, autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip="127.0.0.1", protocol='tcp', port=6633)
    net.build()
    net.start()
    info('*** Running CLI\n')
    CLI(net)


    info('*** Stopping network\n')
    net.stop()

# Example command to run: sudo python3 part1/p1_topo.py
if __name__ == '__main__':
    # Set log level to display Mininet output
    setLogLevel('info')
    run()

