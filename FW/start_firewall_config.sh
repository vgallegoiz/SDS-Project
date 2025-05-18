#!/bin/bash

# Enable the FW
curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001

# See that it is enabled
curl http://localhost:8080/firewall/module/status

# Enable IPv4 traffic on VLAN2 (no VLANs in topology, applies to all traffic)
curl -X POST -H "Content-Type: application/json" -d '{"dl_type":"IPv4","nw_src":"10.0.0.0/8","priority":"1","actions":"ALLOW"}' http://localhost:8080/firewall/rules/0000000000000001
curl -X POST -H "Content-Type: application/json" -d '{"dl_type":"IPv4","nw_dst":"10.0.0.0/8","priority":"1","actions":"ALLOW"}' http://localhost:8080/firewall/rules/0000000000000001
