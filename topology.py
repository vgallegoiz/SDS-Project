from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

def vlanTopology():
    # Creamos la red con controlador remoto (Ryu)
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)
    
    print("Creating nodes...")
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    # Hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    
    # Un único switch
    s1 = net.addSwitch('s1')

    print("Creating links...")
    # Agregar los hosts al switch sin VLAN todavía
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    print("Starting network...")
    net.build()
    controller.start()
    s1.start([controller])

    # Configurar los puertos del switch con VLANs (usando OVS)
    print("Configuring VLANs on switch ports...")
    s1.cmd('ovs-vsctl set port s1-eth1 tag=2')   # h1 -> VLAN 2
    s1.cmd('ovs-vsctl set port s1-eth2 tag=2')   # h2 -> VLAN 2
    s1.cmd('ovs-vsctl set port s1-eth3 tag=110') # h3 -> VLAN 110
    s1.cmd('ovs-vsctl set port s1-eth4 tag=110') # h4 -> VLAN 110

    print("Running CLI...")
    CLI(net)

    print("Stopping network...")
    net.stop()

if __name__ == '__main__':
    vlanTopology()

