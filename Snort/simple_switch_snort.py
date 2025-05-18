# (Same as last provided, with added debug print)
from __future__ import print_function

import array
import json
import re
import requests

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib import snortlib
from ryu.lib import dpid as dpid_lib

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 5
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_ips = set()
        self.blocked_ips.clear()
        self.logger.info("Starting SimpleSwitchSnort with specific IP blocking for SIDs 1100001, 1100002")

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        self.firewall_base_url = 'http://localhost:8080/firewall/rules/'
        self.firewall_headers = {'Content-Type': 'application/json'}

    def packet_print(self, pkt):
        try:
            pkt = packet.Packet(array.array('B', pkt))
            eth = pkt.get_protocol(ethernet.ethernet)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)

            log_msg = "Packet details:\n"
            if eth:
                log_msg += f"  Ethernet: src={eth.src}, dst={eth.dst}\n"
            if ipv4_pkt:
                log_msg += f"  IPv4: src={ipv4_pkt.src}, dst={ipv4_pkt.dst}, proto={ipv4_pkt.proto}\n"
            if icmp_pkt:
                log_msg += f"  ICMP: type={icmp_pkt.type}, code={icmp_pkt.code}\n"
            if tcp_pkt:
                log_msg += f"  TCP: sport={tcp_pkt.src_port}, dport={tcp_pkt.dst_port}\n"

            self.logger.info(log_msg)
        except Exception as e:
            self.logger.error("Error parsing packet: %s", str(e))

    def get_snort_sid(self, string):
        try:
            return str(string.split(" --- ")[1].rstrip('\x00')).strip()
        except IndexError:
            return None

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        try:
            msg = ev.msg
            alert_msg = msg.alertmsg[0].decode()
            
            sid = self.get_snort_sid(alert_msg)
            
            msg_match = re.search(r'msg:"([^"]+)"', alert_msg)
            alert_description = msg_match.group(1) if msg_match else alert_msg

            self.logger.info("=== Snort Alert ===")
            self.logger.info("Description: %s", alert_description)
            self.logger.info("SID: %s", sid)
            self.logger.info("Full message: %s", alert_msg)

            self.packet_print(msg.pkt)

            if sid in ["1100001", "1100002"]:
                for dpid, datapath in self.datapaths.items():
                    self.block_traffic_based_on_sid(sid, msg.pkt, alert_description, dpid)
            else:
                self.logger.warning("Unsupported SID: %s", sid)

        except Exception as e:
            self.logger.error("Error processing Snort alert: %s", str(e))

    def block_traffic_based_on_sid(self, sid, pkt_data, alert_description, dpid):
        try:
            pkt = packet.Packet(array.array('B', pkt_data))
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            
            if not ipv4_pkt:
                self.logger.warning("Non-IPv4 packet, skipping")
                return

            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            if src_ip in self.blocked_ips:
                self.logger.info("IP %s already blocked for switch %s, skipping", src_ip, dpid)
                return

            rule = {
                "priority": "2000",  # Increased priority
                "dl_type": "IPv4",
                "nw_src": src_ip,
                "nw_dst": dst_ip,
                "actions": "DENY",
                "alert_description": alert_description,
                "sid": sid
            }

            if sid == "1100001":
                rule["nw_proto"] = "ICMP"
            elif sid == "1100002":
                rule["nw_proto"] = "TCP"
                rule["tp_dst"] = "80"

            self.logger.info("Creating firewall rule for SID %s on switch %s: %s", sid, dpid, rule)
            self.add_firewall_rule(rule, dpid)
            self.blocked_ips.add(src_ip)
            self.logger.info("Added IP %s to blocked_ips for switch %s", src_ip, dpid)

        except Exception as e:
            self.logger.error("Error creating block rule for switch %s: %s", dpid, str(e))

    def add_firewall_rule(self, rule, dpid):
        try:
            firewall_url = f"{self.firewall_base_url}{dpid}"
            self.logger.debug("Sending rule to %s: %s", firewall_url, rule)
            response = requests.post(
                firewall_url,
                data=json.dumps(rule),
                headers=self.firewall_headers,
                timeout=5
            )
            
            if response.status_code == 200:
                self.logger.info("Firewall rule added successfully for switch %s", dpid)
                self.logger.debug("Rule details: %s", rule)
                try:
                    response_json = response.json()
                    self.logger.debug("Response: %s", response_json)
                except ValueError:
                    self.logger.warning("Invalid JSON response from firewall API")
            else:
                self.logger.error("Failed to add firewall rule for switch %s. Status: %d, Response: %s",
                                dpid, response.status_code, response.text)
        except requests.exceptions.RequestException as e:
            self.logger.error("Error connecting to firewall API for switch %s: %s", dpid, str(e))
        except Exception as e:
            self.logger.error("Unexpected error for switch %s: %s", dpid, str(e))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_lib.dpid_to_str(datapath.id)

        self.datapaths[dpid] = datapath
        self.logger.info("Switch %s connected", dpid)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.debug("Added flow to switch %s: priority=%d, match=%s, actions=%s",
                         dpid_lib.dpid_to_str(datapath.id), priority, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            dpid = dpid_lib.dpid_to_str(datapath.id)
            self.mac_to_port.setdefault(dpid, {})
            
            self.logger.debug("PacketIn: dpid=%s, src=%s, dst=%s, in_port=%s",
                            dpid, eth.src, eth.dst, in_port)

            self.mac_to_port[dpid][eth.src] = in_port

            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [
                parser.OFPActionOutput(out_port),
                parser.OFPActionOutput(self.snort_port)
            ]

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
                self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)

        except Exception as e:
            self.logger.error("Error processing PacketIn: %s", str(e))
