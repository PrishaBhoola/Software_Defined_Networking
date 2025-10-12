#!/usr/bin/env python3
"""
WORKING Shortest Path Controller for Part 2
Complete implementation with proper error handling
"""

import json
import sys
import os
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

# Import our custom modules
from dijkstra import DijkstraPathFinder
from network_graph import NetworkGraph


class WorkingShortestPathController(app_manager.RyuApp):
    """Working controller with complete implementation"""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(WorkingShortestPathController, self).__init__(*args, **kwargs)

        # Load configuration
        self.config = self.load_config()
        self.ecmp_enabled = self.config.get('ecmp', False)

        # Initialize network components
        self.network_graph = NetworkGraph(self.config)
        self.path_finder = DijkstraPathFinder(self.network_graph)

        # MAC learning table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Flow tracking for ECMP
        self.flow_paths = {}
        self.path_usage = defaultdict(int)

        # Store datapaths for flow installation
        self.datapaths = {}

        self.logger.info("Working Shortest Path Controller initialized")
        self.logger.info(f"ECMP enabled: {self.ecmp_enabled}")

    def load_config(self):
        """Load configuration from config.json"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), 'config.json')
            with open(config_path, 'r') as f:
                config = json.load(f)
            self.logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return {"ecmp": False, "nodes": ["s1", "s2", "s3", "s4", "s5", "s6"], "weight_matrix": []}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)

        # Store datapath
        self.datapaths[dpid] = datapath

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Initialize MAC learning table
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info(f"Switch {dpid} connected")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packet-in events"""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = format(datapath.id, "d").zfill(16)

        # Learn source MAC
        known_dpid, _ = self.find_destination(src_mac)
        if known_dpid is None:  
            self.mac_to_port[dpid][src_mac] = in_port

        self.logger.info(f"Packet from {src_mac} to {dst_mac} at switch {dpid} port {in_port}")

        # Handle broadcast/multicast
        if dst_mac.startswith("ff:ff:ff:ff:ff:ff") or dst_mac.startswith("01:"):
            self.flood_packet(datapath, msg, in_port)
            return

        # Find destination
        dst_dpid, dst_port = self.find_destination(dst_mac)

        if dst_dpid is None:
            # Destination unknown - flood
            self.logger.info(f"Destination {dst_mac} unknown, flooding")
            self.flood_packet(datapath, msg, in_port)
            return

        # Calculate shortest path
        src_switch = self.dpid_to_node(dpid)
        dst_switch = self.dpid_to_node(dst_dpid)

        # Same switch handling
        if src_switch == dst_switch:
            self.send_packet_out(datapath, msg, dst_port)
            return

        # Find path
        if self.ecmp_enabled:
            paths = self.path_finder.find_all_shortest_paths(src_switch, dst_switch)
            chosen_path = self.select_path_for_flow(src_mac, dst_mac, paths)
        else:
            chosen_path = self.path_finder.find_shortest_path(src_switch, dst_switch)

        if not chosen_path:
            self.logger.warning(f"No path found from {src_switch} to {dst_switch}")
            self.flood_packet(datapath, msg, in_port)
            return

        self.logger.info(f"Chosen path: {' -> '.join(chosen_path)}")

        # Install flows along the path
        self.install_path_flows(chosen_path, src_mac, dst_mac, dst_port)

        # Forward the packet
        next_port = self.get_next_hop_port(dpid, chosen_path)
        if next_port is not None:
            self.send_packet_out(datapath, msg, next_port)
        else:
            self.logger.error(f"Cannot determine next hop port for {dpid} in path {chosen_path}")
            self.flood_packet(datapath, msg, in_port)

    def select_path_for_flow(self, src_mac, dst_mac, paths):
        """Select path for flow with ECMP"""
        if not paths:
            return []

        if len(paths) == 1:
            return paths[0]

        flow_key = f"{src_mac}-{dst_mac}"

        if flow_key not in self.flow_paths:
            # Select least used path for load balancing
            min_usage = min(self.path_usage.get(str(path), 0) for path in paths)
            candidate_paths = [path for path in paths 
                             if self.path_usage.get(str(path), 0) == min_usage]

            chosen_path = candidate_paths[hash(flow_key) % len(candidate_paths)]
            self.flow_paths[flow_key] = chosen_path
            self.path_usage[str(chosen_path)] += 1

            self.logger.info(f"ECMP selected path for {flow_key}: {' -> '.join(chosen_path)}")

        return self.flow_paths[flow_key]

    def install_path_flows(self, path, src_mac, dst_mac, dst_port):
        """Install flow rules along the path"""
        for i, node in enumerate(path):
            dpid = self.node_to_dpid(node)
            if dpid not in self.datapaths:
                continue

            datapath = self.datapaths[dpid]
            parser = datapath.ofproto_parser

            # Determine output port
            if i == len(path) - 1:
                # Last switch - output to destination host
                out_port = dst_port
            else:
                # Intermediate switch - output to next switch
                next_node = path[i + 1]
                out_port = self.network_graph.get_port_between_nodes(node, next_node)

            if out_port is not None:
                match = parser.OFPMatch(eth_dst=dst_mac)
                actions = [parser.OFPActionOutput(out_port)]
                # Use higher priority than table-miss
                self.add_flow(datapath, 100, match, actions, idle_timeout=30)

                self.logger.info(f"Installed flow at {node}: {dst_mac} -> port {out_port}")
            else:
                self.logger.error(f"Cannot determine output port for {node} -> {next_node if i < len(path)-1 else 'host'}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        """Add flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match, instructions=inst,
                                  idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def find_destination(self, dst_mac):
        """Find destination switch and port"""
        for dpid, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                return dpid, mac_table[dst_mac]
        return None, None

    def dpid_to_node(self, dpid):
        """Convert datapath ID to node name"""
        return f's{int(dpid)}'

    def node_to_dpid(self, node):
        """Convert node name to datapath ID"""
        return format(int(node[1:]), "d").zfill(16)

    def get_next_hop_port(self, current_dpid, path):
        """Get output port for next hop"""
        current_node = self.dpid_to_node(current_dpid)
        try:
            idx = path.index(current_node)
            if idx < len(path) - 1:
                next_node = path[idx + 1]
                port = self.network_graph.get_port_between_nodes(current_node, next_node)
                return port
        except (ValueError, IndexError) as e:
            self.logger.error(f"Error finding next hop: {e}")
        return None

    def flood_packet(self, datapath, msg, in_port):
        """Flood packet to all ports except input port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.debug(f"Flooded packet at switch {format(datapath.id, 'd').zfill(16)}")

    def send_packet_out(self, datapath, msg, out_port):
        """Send packet out specific port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.debug(f"Sent packet out port {out_port}")
