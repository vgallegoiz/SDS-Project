sudo ip link add name s1-snort type dummy
sudo ip link set s1-snort up
sudo ovs-vsctl add-port s1 s1-snort
sudo ovs-ofctl show s1
