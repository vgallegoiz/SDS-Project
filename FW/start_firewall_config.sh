#!/bin/bash

# Enable the FW
curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001

# See that it is enabled
curl http://localhost:8080/firewall/module/status

# Enable IPv4 traffic on VLAN2 (no VLANs in topology, applies to all traffic)

