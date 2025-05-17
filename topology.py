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
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')

    # Switch
    s1 = net.addSwitch('s1')

    print("Creating links...")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    print("Starting network...")
    net.build()
    controller.start()
    s1.start([controller])

    print("Configuring VLAN interfaces on hosts...")

    # Configuración de VLAN en hosts
    # VLAN 2: h1 y h2
    for h, ip in [(h1, '10.0.0.1/8'), (h2, '10.0.0.2/8')]:
        h.cmd('ip addr del {} dev {}-eth0'.format(ip, h.name))
        h.cmd('ip link add link {}-eth0 name {}-eth0.2 type vlan id 2'.format(h.name, h.name))
        h.cmd('ip addr add {} dev {}-eth0.2'.format(ip, h.name))
        h.cmd('ip link set dev {}-eth0.2 up'.format(h.name))

    # VLAN 110: h3 y h4
    for h, ip in [(h3, '10.0.0.3/8'), (h4, '10.0.0.4/8')]:
        h.cmd('ip addr del {} dev {}-eth0'.format(ip, h.name))
        h.cmd('ip link add link {}-eth0 name {}-eth0.110 type vlan id 110'.format(h.name, h.name))
        h.cmd('ip addr add {} dev {}-eth0.110'.format(ip, h.name))
        h.cmd('ip link set dev {}-eth0.110 up'.format(h.name))

    print("Running CLI...")
    CLI(net)

    print("Stopping network...")
    net.stop()

if __name__ == '__main__':
    vlanTopology()

