from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class CustomTopo(Topo):
    def build(self, option='a'):
        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Add links based on the option
        if option == 'c':
            # Configure links with specific bandwidths
            self.addLink(s1, s2, bw=100)
            self.addLink(s2, s3, bw=50)
            self.addLink(s3, s4, bw=100)
        else:
            # Default configuration
            self.addLink(s1, s2)
            self.addLink(s2, s3)
            self.addLink(s3, s4)

        # Host connections
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s4)

def configure_network(option='a'):
    topo = CustomTopo(option=option)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = configure_network()
    dumpNodeConnections(net.hosts)
    net.pingAll()
    net.stop()