# Enable the FW
curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001

# See that it is enabled
curl http://localhost:8080/firewall/module/status

# Enable traffic on VLAN2
curl -X POST -d '{"nw_src": "10.0.0.0/8"}' http://localhost:8080/firewall/rules/0000000000000001/2
curl -X POST -d '{"nw_dst": "10.0.0.0/8"}' http://localhost:8080/firewall/rules/0000000000000001/2

# Enable traffic on VLAN110
curl -X POST -d '{"nw_src": "10.0.0.0/8"}' http://localhost:8080/firewall/rules/0000000000000001/110
curl -X POST -d '{"nw_dst": "10.0.0.0/8"}' http://localhost:8080/firewall/rules/0000000000000001/110

