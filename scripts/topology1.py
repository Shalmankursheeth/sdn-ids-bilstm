#!/usr/bin/python


from mininet.topo import Topo
from mininet.net import Mininet, Host
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.link import TCLink
from time import sleep

'''
      s1
  /        \
s2           s3
|
h1,h2,        server1,server2
h3,h4

'''


class SingleSwitchTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1',dpid='1')
        s2 = self.addSwitch('s2',dpid='2')
        s3 = self.addSwitch('s3',dpid='3')
        h1 = self.addHost('h1', ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost('h2', ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost('h3', ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost('h4', ip="10.0.0.4/24", mac="00:00:00:00:00:04")
        server1 = self.addHost('server1', ip="10.0.0.5/24", mac="00:00:00:00:00:05")
        server2 = self.addHost('server2', ip="10.0.0.6/24", mac="00:00:00:00:00:06")
    

        self.addLink(h1, s2, cls=TCLink, bw=10)
        self.addLink(h2, s2, cls=TCLink, bw=10)
        self.addLink(h3, s2, cls=TCLink, bw=10)
        self.addLink(h4, s2, cls=TCLink, bw=10)

        self.addLink(server1, s3, cls=TCLink, bw=10)
        self.addLink(server2, s3, cls=TCLink, bw=10)


        self.addLink(s1, s2, cls=TCLink, bw=10)        
        self.addLink(s1, s3, cls=TCLink, bw=10)        


if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    #sleep(5)
    #net.pingAll()
    server1 = net.get('server1')
    server1.cmd('iperf -u -s &')
    server1.cmd('iperf -s -p 80 &')
    server2 = net.get('server2')
    server2.cmd('iperf -u -s &')
    server2.cmd('iperf -s -p 80 &')
    CLI(net)
    net.stop()