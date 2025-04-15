from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib import hub
import csv
from ml import MachineLearningAlgo

# 0 - Data collection, 1 - Detection
APP_MODE = 0
TRAFFIC_TYPE = 0
DETECTION_INTERVAL = 30

def init_csv():
    fname = "result.csv"
    with open(fname, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["flow_duration", "ip_proto", "src_port", "dst_port", "byte_count", "packet_count", "type"])

def update_csv(data):
    fname = "result.csv"
    with open(fname, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(data)

class DDOSMLApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDOSMLApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.known_arp_ips = {}
        self.mlobj = MachineLearningAlgo() if APP_MODE == 1 else None
        if APP_MODE == 0:
            init_csv()
        self.monitor_thread = hub.spawn(self.monitor)


    def monitor(self):
        self.logger.info("Starting flow monitoring thread")
        while True:
            hub.sleep(DETECTION_INTERVAL)
            for datapath in self.datapaths.values():
                ofp_parser = datapath.ofproto_parser
                req = ofp_parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply], MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            if stat.priority != 1:
                continue  # Only check priority 1 (data flows)
            ip_proto = stat.match['ip_proto']
            self.ddos_detection(
                ev.msg.datapath.id, 
                stat.match['eth_src'], 
                stat.match.get('eth_dst', None), 
                stat.duration_sec, 
                ip_proto,
                stat.match.get('tcp_src' if ip_proto == 6 else 'udp_src', 0),
                stat.match.get('tcp_dst' if ip_proto == 6 else 'udp_dst', 0),
                stat.byte_count,
                stat.packet_count
            )

    def ddos_detection(self, datapath_id, source_mac, destination_mac, duration, ip_proto, src_port, dst_port, byte_count, packet_count):
        self.logger.info("Flow parameters: duration=%s, ip_proto=%s, src_port=%s, dst_port=%s, byte_count=%s, packet_count=%s",
                         duration, ip_proto, src_port, dst_port, byte_count, packet_count)
        data = [duration, ip_proto, src_port, dst_port, byte_count, packet_count, TRAFFIC_TYPE]

        if APP_MODE == 0:
            update_csv(data)
        else:
            ids = self.mlobj.classify([[duration, ip_proto, src_port, dst_port, byte_count, packet_count]])[0]
            if ids == 1:
                self.logger.info("DDoS attack detected from %s; blocking it", source_mac)
                self.block_traffic(datapath_id, source_mac)
            elif ids == 2:
                self.logger.info("ARP Spoofing (MITM) detected from %s to %s; blocking it", source_mac, destination_mac)
                self.block_traffic(datapath_id, source_mac, destination_mac)

    def block_traffic(self, dpid, src, dst=None):
        datapath = self.datapaths[dpid]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src) if dst is None else parser.OFPMatch(eth_src=src, eth_dst=dst)
        actions = []
        self.add_flow(datapath, priority=100, match=match, actions=actions, idle_timeout=120)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = arp_pkt.src_ip
            src_mac = arp_pkt.src_mac

            if src_ip in self.known_arp_ips and self.known_arp_ips[src_ip] != src_mac:
                self.logger.warning("ARP Spoofing detected: IP %s is associated with MAC %s instead of %s",
                                    src_ip, src_mac, self.known_arp_ips[src_ip])
                self.ddos_detection(dpid, src_mac, None, 0, "ARP", 0, 0, 0, 0)
            else:
                self.known_arp_ips[src_ip] = src_mac
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            ip_proto = ip_pkt.proto
            src_port = dst_port = 0
            if ip_proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port
            elif ip_proto == in_proto.IPPROTO_UDP:
                udp_pkt = pkt.get_protocol(udp.udp)
                src_port, dst_port = udp_pkt.src_port, udp_pkt.dst_port
            byte_count = len(msg.data)
            self.ddos_detection(dpid, src, dst, 0, ip_proto, src_port, dst_port, byte_count, 1)

        out_port = self.mac_to_port[dpid].get(dst, datapath.ofproto.OFPP_FLOOD)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)
