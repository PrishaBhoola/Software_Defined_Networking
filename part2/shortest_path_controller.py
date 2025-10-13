#!/usr/bin/env python3

"""
COMBINED Shortest Path Controller for Part 2
All modules in one file for easy deployment
Fixed ECMP implementation for proper load balancing
"""

import json
import sys
import os
import random
import heapq
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


# ===============================
# NETWORK GRAPH MODULE
# ===============================

class NetworkGraph:
    """Network graph utilities with correct port mappings"""

    def __init__(self, config):
        self.nodes = config.get('nodes', [])
        self.weight_matrix = config.get('weight_matrix', [])
        self.adjacency_matrix = self._build_adjacency_matrix()
        self.port_mapping = self._build_port_mapping()

    def _build_adjacency_matrix(self):
        """Build adjacency matrix from weight matrix"""
        size = len(self.nodes)
        adj_matrix = {}

        for i in range(size):
            node_i = self.nodes[i]
            adj_matrix[node_i] = {}
            for j in range(size):
                node_j = self.nodes[j]
                weight = self.weight_matrix[i][j] if i < len(self.weight_matrix) and j < len(self.weight_matrix[i]) else 0
                if weight > 0:  # There's a connection
                    adj_matrix[node_i][node_j] = weight

        return adj_matrix

    def _build_port_mapping(self):
        """FIXED port mapping based on p2_topo.py link creation order"""
        port_map = {}

        # Based on the exact order in p2_topo.py:
        # 1. h1 -> s1 (port 1 on s1)
        # 2. h2 -> s6 (port 1 on s6)  
        # 3. s1 -> s2 (port 2 on s1, port 1 on s2)
        # 4. s1 -> s3 (port 3 on s1, port 1 on s3)
        # 5. s2 -> s4 (port 2 on s2, port 1 on s4)
        # 6. s3 -> s5 (port 2 on s3, port 1 on s5)
        # 7. s4 -> s6 (port 2 on s4, port 2 on s6)
        # 8. s5 -> s6 (port 2 on s5, port 3 on s6)

        port_map['s1'] = {'h1': 1, 's2': 2, 's3': 3}
        port_map['s2'] = {'s1': 1, 's4': 2}
        port_map['s3'] = {'s1': 1, 's5': 2}
        port_map['s4'] = {'s2': 1, 's6': 2}
        port_map['s5'] = {'s3': 1, 's6': 2}
        port_map['s6'] = {'h2': 1, 's4': 2, 's5': 3}

        return port_map

    def get_neighbors(self, node):
        """Get neighbors of a node with their weights"""
        return self.adjacency_matrix.get(node, {})

    def get_weight(self, node1, node2):
        """Get weight between two nodes"""
        return self.adjacency_matrix.get(node1, {}).get(node2, float('inf'))

    def get_port_between_nodes(self, node1, node2):
        """Get port number for connection from node1 to node2"""
        return self.port_mapping.get(node1, {}).get(node2)

    def get_all_nodes(self):
        """Get all nodes in the network"""
        return self.nodes.copy()


# ===============================
# DIJKSTRA ALGORITHM MODULE  
# ===============================

class DijkstraPathFinder:
    """Dijkstra's Algorithm Implementation with ECMP support"""

    def __init__(self, network_graph):
        self.graph = network_graph

    def find_shortest_path(self, source, destination):
        """Find single shortest path between source and destination"""
        paths = self.find_all_shortest_paths(source, destination)
        return paths[0] if paths else []

    def find_all_shortest_paths(self, source, destination):
        """Find all shortest paths between source and destination"""
        if source == destination:
            return [[source]]

        # Initialize distances and previous nodes
        distances = {node: float('inf') for node in self.graph.get_all_nodes()}
        distances[source] = 0

        # Track all possible previous nodes for each node (for ECMP)
        previous = defaultdict(list)

        # Priority queue: (distance, node)
        pq = [(0, source)]
        visited = set()

        while pq:
            current_dist, current_node = heapq.heappop(pq)

            if current_node in visited:
                continue

            visited.add(current_node)

            # If we reached destination, stop
            if current_node == destination:
                break

            # Check all neighbors
            for neighbor, weight in self.graph.get_neighbors(current_node).items():
                distance = current_dist + weight

                if distance < distances[neighbor]:
                    # Found shorter path
                    distances[neighbor] = distance
                    previous[neighbor] = [current_node]
                    heapq.heappush(pq, (distance, neighbor))
                elif distance == distances[neighbor]:
                    # Found equal length path
                    if current_node not in previous[neighbor]:
                        previous[neighbor].append(current_node)

        # Reconstruct all shortest paths
        all_paths = []
        self._build_paths(destination, source, previous, [destination], all_paths)
        return all_paths

    def _build_paths(self, current, source, previous, current_path, all_paths):
        """Recursively build all paths from destination to source"""
        if current == source:
            all_paths.append(current_path[::-1])  # Reverse to get source->dest
            return

        for prev_node in previous[current]:
            self._build_paths(prev_node, source, previous,
                             current_path + [prev_node], all_paths)


# ===============================
# MAIN CONTROLLER  
# ===============================

class CombinedShortestPathController(app_manager.RyuApp):
    """Combined controller with all modules included"""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CombinedShortestPathController, self).__init__(*args, **kwargs)

        # Load configuration
        self.config = self.load_config()
        self.ecmp_enabled = self.config.get('ecmp', False)

        # Initialize network components
        self.network_graph = NetworkGraph(self.config)
        self.path_finder = DijkstraPathFinder(self.network_graph)

        # MAC learning table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # IMPROVED ECMP tracking
        self.flow_paths = {}  # {flow_key: path}
        self.path_counter = 0  # Round-robin counter for better distribution
        self.active_flows = defaultdict(int)  # Track flows per path

        # Store datapaths for flow installation
        self.datapaths = {}

        self.logger.info("Combined Shortest Path Controller initialized")
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
            # Default configuration
            return {
                "ecmp": False,
                "nodes": ["s1", "s2", "s3", "s4", "s5", "s6"],
                "weight_matrix": [
                    [0, 10, 10, 0, 0, 0],
                    [10, 0, 0, 20, 0, 0],
                    [10, 0, 0, 0, 20, 0],
                    [0, 20, 0, 0, 0, 10],
                    [0, 0, 20, 0, 0, 10],
                    [0, 0, 0, 10, 10, 0]
                ]
            }

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

        # Find path with improved ECMP
        if self.ecmp_enabled:
            paths = self.path_finder.find_all_shortest_paths(src_switch, dst_switch)
            chosen_path = self.improved_select_path_for_flow(src_mac, dst_mac, paths)
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

    def improved_select_path_for_flow(self, src_mac, dst_mac, paths):
        """IMPROVED path selection for better load balancing"""
        if not paths:
            return []

        if len(paths) == 1:
            return paths[0]

        # Create flow key based on MAC addresses
        flow_key = f"{src_mac}-{dst_mac}"

        if flow_key not in self.flow_paths:
            if self.ecmp_enabled:
                # STRATEGY: Round-robin for better distribution
                # This ensures parallel flows are distributed across paths
                chosen_path = paths[self.path_counter % len(paths)]
                self.path_counter += 1

                self.flow_paths[flow_key] = chosen_path
                self.active_flows[str(chosen_path)] += 1

                self.logger.info(f"ECMP round-robin selected path #{(self.path_counter-1) % len(paths)} "
                               f"for {flow_key}: {' -> '.join(chosen_path)}")
            else:
                # No ECMP - use first path
                chosen_path = paths[0]
                self.flow_paths[flow_key] = chosen_path

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
                # IMPORTANT: Use src+dst match for better flow granularity
                match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                actions = [parser.OFPActionOutput(out_port)]

                # Use higher priority and shorter timeout for better responsiveness
                self.add_flow(datapath, 100, match, actions, idle_timeout=10)
                self.logger.info(f"Installed flow at {node}: {src_mac}->{dst_mac} -> port {out_port}")
            else:
                self.logger.error(f"Cannot determine output port for {node} -> "
                                f"{path[i+1] if i < len(path)-1 else 'host'}")

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
