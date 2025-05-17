#!/bin/bash

# Set the working directory
workdir=$(pwd)

# Create directories if they don't already exist
mkdir -p "$workdir/tools"
mkdir -p "$workdir/tmp"

# Update the package list
sudo apt update

# Install Ryu if not already installed
if [ ! -d "$workdir/tools/ryu" ]; then
    git clone https://github.com/osrg/ryu.git "$workdir/tools/ryu"
    sudo pip3 install ryu
else
    echo "Ryu is already installed."
fi

# Install InfluxDB if not already downloaded
influxdb_deb="$workdir/tmp/influxdb_1.8.4_amd64.deb"
if [ ! -f "$influxdb_deb" ]; then
    wget -O "$influxdb_deb" https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb
fi

sudo dpkg -i "$influxdb_deb"
sudo apt install -y python3-influxdb
sudo systemctl start influxdb

# Install Telegraf
telegraf_deb="$workdir/tmp/telegraf_1.17.3-1_amd64.deb"
if [ ! -f "$telegraf_deb" ]; then
    wget -O "$telegraf_deb" https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb
fi

sudo dpkg -i "$telegraf_deb"

# Replace config if needed
if [ -f "/etc/telegraf/telegraf.conf" ]; then
    sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bak
fi

# Only copy config if it exists
if [ -f "$workdir/telegraf/telegraf.conf" ]; then
    sudo cp "$workdir/telegraf/telegraf.conf" /etc/telegraf/
else
    echo "Advertencia: No se encontró el archivo de configuración telegraf.conf en $workdir/telegraf/"
fi

sudo systemctl restart telegraf

# Install Grafana
grafana_deb="$workdir/tmp/grafana_7.4.3_amd64.deb"
if [ ! -f "$grafana_deb" ]; then
    wget -O "$grafana_deb" https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb
fi

sudo apt install -y libfontconfig1
sudo dpkg -i "$grafana_deb"
sudo systemctl start grafana-server

echo "Setup script completed."

