# SDS Project

## Requirements
`python3 -m venv .venv`

`source .venv/bin/activate/`

`pip3 install -r requirements.txt`

`./start/start_requirementes.sh`

`sudo apt-get install snort -y`

Specify the interface (ens33) and the subnet (10.0.0.0/16)

SDS Project

This project is part of the Master's program in Cybersecurity and aims to implement a proactive intrusion detection and mitigation environment for Software-Defined Networks (SDN) using Snort and Ryu through their REST APIs.

🛠️ Requirements

Make sure you are in an environment with Python 3 and have administrative (sudo) access. The following steps describe how to set up the environment:

    Create and activate the virtual environment

python3 -m venv .venv
source .venv/bin/activate

    Install Python dependencies

pip3 install -r requirements.txt

    Run the preparation scripts

./start/start_requirementes.sh

    Install Snort

sudo apt-get install snort -y

During Snort installation, make sure to correctly specify:

    Network interface: ens33

    Subnet: 10.0.0.0/16

You can configure this either by editing /etc/snort/snort.debian.conf or by using command-line arguments.
