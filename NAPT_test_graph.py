from mininet.topo import Topo

class MyTopo(Topo):
    "Simple_topology_example"
    def __init__(self):
        "Create_custom_topo."

        Topo.__init__(self)

        host1 = self.addHost(name = 'host1',ip = '192.168.0.1/16')
        host2 = self.addHost(name = 'host2',ip = '192.168.0.2/16')
        host3 = self.addHost(name = 'host3',ip = '192.168.0.3/16')

        server1 = self.addHost(name = 'server1', ip = '192.168.1.1/16')

        switch1 = self.addSwitch('s1')
        router1 = self.addSwitch('r2')

        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch1)
        self.addLink(switch1, router1)
        self.addLink(router1, server1)

topos = {'mytopo':MyTopo}