# SDS Project

This project is part of the Master's program in Cybersecurity and aims to implement a proactive intrusion detection and mitigation environment for Software-Defined Networks (SDN) using Snort and Ryu through their REST APIs.

## 🖥️ Network Topology


## 🛠️ Requirements

Make sure you are in an environment with Python 3 and have administrative (sudo) access. The following steps describe how to set up the environment:

Create and activate the virtual environment

    python3 -m venv .venv
    source .venv/bin/activate

Install Python dependencies

    pip3 install -r requirements.txt

Run the preparation scripts

    chmod +x ./start/start_requirements.sh
    ./start/start_requirements.sh

Install Snort

    sudo apt-get install snort -y

During Snort installation, make sure to correctly specify:

    Network interface: ens33

    Subnet: 10.0.0.0/16

It is necessary to copy the rules from *Snort/Myrules.rules* and add the route to the */etc/snort/snort.conf/*

Install Hping3

    sudo apt-get install hping3 -y
    

## To start the Project

Clear Mininet cache and execute the topology and Mininet

	sudo mn -c && sudo python3 topology.py

Start the RYU controller

	sudo ryu-manager Snort/simple_switch_snort.py FW/rest_firewall.py # Faltará poner la parte de Telegraf (Telegraf/simple_monitor_13_telegraf.py)

Execute the *FW/start_firewall_config.sh* to configure the FW and the necessary rules. The initial rules permits all the traffic inside the VLAN but NOT between VLANs.
	
	./FW/start_firewall_config.sh

Finally, execute Snort

    sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf

## Perform the attacks

We need to open a terminal on h1

    xterm h1

And execute the script *dos.py* by selecting the ICMP or TCP

    python3 attacks/dos.py

To execute the scan, it is necessary to fill in the CSV with the IP and the ports that we want to scan and execute it

    python3 attacks/scan.py