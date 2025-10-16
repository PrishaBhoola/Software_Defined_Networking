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
from ryu.lib.packet import ether_types, ipv4, tcp
from ryu.topology import event
from ryu.topology.api import get_switch, get_link


# ===============================
# NETWORK GRAPH MODULE
# ===============================

class NetworkGraph:
    """Network graph utilities with dynamic topology discovery"""

    def __init__(self):
        self.adjacency_matrix = {}
        self.port_mapping = {}
        self.link_costs = {}  # Store link costs (weights)

    def add_switch(self, switch_name):
        """Add a switch to the graph"""
        if switch_name not in self.adjacency_matrix:
            self.adjacency_matrix[switch_name] = {}
            self.port_mapping[switch_name] = {}

    def add_link(self, src_switch, dst_switch, src_port, dst_port, weight=1):
        """Add a bidirectional link between switches"""
        # Add switches if they don't exist
        self.add_switch(src_switch)
        self.add_switch(dst_switch)
        
        # Add link with weight
        self.adjacency_matrix[src_switch][dst_switch] = weight
        
        # Store port mapping
        self.port_mapping[src_switch][dst_switch] = src_port
        
        # Store link cost
        link_key = (src_switch, dst_switch)
        self.link_costs[link_key] = weight

    def add_host_connection(self, switch_name, host_name, port):
        """Add host connection to switch"""
        self.add_switch(switch_name)
        self.port_mapping[switch_name][host_name] = port

    def update_link_weight(self, src_switch, dst_switch, weight):
        """Update the weight of an existing link"""
        if src_switch in self.adjacency_matrix and dst_switch in self.adjacency_matrix[src_switch]:
            self.adjacency_matrix[src_switch][dst_switch] = weight
            link_key = (src_switch, dst_switch)
            self.link_costs[link_key] = weight

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
        return list(self.adjacency_matrix.keys())

    def print_topology(self, logger):
        """Print current topology for debugging"""
        logger.info("=" * 50)
        logger.info("Current Network Topology:")
        logger.info(f"Switches: {self.get_all_nodes()}")
        logger.info("Links:")
        for src in self.adjacency_matrix:
            for dst, weight in self.adjacency_matrix[src].items():
                port = self.port_mapping[src].get(dst, "?")
                logger.info(f"  {src} --[port {port}, weight {weight}]--> {dst}")
        logger.info("=" * 50)


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
# MAIN CONTROLLER WITH DYNAMIC TOPOLOGY
# ===============================

class DynamicShortestPathController(app_manager.RyuApp):
    """Controller with dynamic topology discovery"""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicShortestPathController, self).__init__(*args, **kwargs)

        # Load configuration
        self.config = self.load_config()
        self.ecmp_enabled = self.config.get('ecmp', False)
        self.weight_matrix = self.config.get('weight_matrix', None)
        self.node_list = self.config.get('nodes', None)

        # Initialize network components
        self.network_graph = NetworkGraph()
        self.path_finder = DijkstraPathFinder(self.network_graph)

        # MAC learning table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # ECMP tracking
        self.flow_paths = {}
        self.path_counter = 0
        self.tcp_connection_counter = 0

        # Store datapaths for flow installation
        self.datapaths = {}

        # Topology discovery state
        self.topology_discovered = False

        self.logger.info("Dynamic Shortest Path Controller initialized")
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
            return {"ecmp": False}

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

        # Add switch to topology
        switch_name = self.dpid_to_node(dpid)
        self.network_graph.add_switch(switch_name)

        self.logger.info(f"Switch {dpid} ({switch_name}) connected")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        """Handle new switch entering the topology"""
        switch = ev.switch
        dpid = format(switch.dp.id, "d").zfill(16)
        switch_name = self.dpid_to_node(dpid)
        
        self.network_graph.add_switch(switch_name)
        self.logger.info(f"Topology event: Switch {switch_name} entered")
        
        # Trigger topology update
        self.discover_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        """Handle link addition event"""
        link = ev.link
        src_switch = self.dpid_to_node(format(link.src.dpid, "d").zfill(16))
        dst_switch = self.dpid_to_node(format(link.dst.dpid, "d").zfill(16))
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        # Determine weight for this link
        weight = self.get_link_weight(src_switch, dst_switch)

        # Add link to graph
        self.network_graph.add_link(src_switch, dst_switch, src_port, dst_port, weight)
        
        self.logger.info(f"Topology event: Link added {src_switch}:{src_port} <--> {dst_switch}:{dst_port} (weight={weight})")
        
        # Mark topology as discovered
        self.topology_discovered = True
        self.network_graph.print_topology(self.logger)

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        """Handle link deletion event"""
        link = ev.link
        src_switch = self.dpid_to_node(format(link.src.dpid, "d").zfill(16))
        dst_switch = self.dpid_to_node(format(link.dst.dpid, "d").zfill(16))
        
        self.logger.info(f"Topology event: Link deleted {src_switch} <--> {dst_switch}")
        
        # Trigger topology rediscovery
        self.discover_topology()

    def discover_topology(self):
        """Discover current network topology"""
        switches = get_switch(self)
        links = get_link(self)

        # Clear and rebuild topology
        self.network_graph = NetworkGraph()
        self.path_finder = DijkstraPathFinder(self.network_graph)

        # Add all switches
        for switch in switches:
            dpid = format(switch.dp.id, "d").zfill(16)
            switch_name = self.dpid_to_node(dpid)
            self.network_graph.add_switch(switch_name)

        # Add all links with weights
        for link in links:
            src_switch = self.dpid_to_node(format(link.src.dpid, "d").zfill(16))
            dst_switch = self.dpid_to_node(format(link.dst.dpid, "d").zfill(16))
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            weight = self.get_link_weight(src_switch, dst_switch)
            self.network_graph.add_link(src_switch, dst_switch, src_port, dst_port, weight)

        self.topology_discovered = True
        self.logger.info("Topology discovery completed")
        self.network_graph.print_topology(self.logger)

    def get_link_weight(self, src_switch, dst_switch):
        """Get link weight from config or use default"""
        if self.weight_matrix and self.node_list:
            try:
                src_idx = self.node_list.index(src_switch)
                dst_idx = self.node_list.index(dst_switch)
                weight = self.weight_matrix[src_idx][dst_idx]
                return weight if weight > 0 else 1
            except (ValueError, IndexError):
                pass
        
        # Default weight
        return 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packet-in events with TCP port awareness"""
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

        # Wait for topology discovery
        if not self.topology_discovered:
            self.logger.debug("Topology not yet discovered, flooding packet")
            self.flood_packet(datapath, msg, in_port)
            return

        # Learn source MAC
        known_dpid, _ = self.find_destination(src_mac)
        if known_dpid is None:
            self.mac_to_port[dpid][src_mac] = in_port
            # Add host connection to topology
            switch_name = self.dpid_to_node(dpid)
            host_name = f"h_{src_mac.replace(':', '')}"
            self.network_graph.add_host_connection(switch_name, host_name, in_port)

        # Extract TCP port information if available
        tcp_src_port = None
        tcp_dst_port = None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and tcp_pkt:
            tcp_src_port = tcp_pkt.src_port
            tcp_dst_port = tcp_pkt.dst_port
            self.logger.info(f"TCP packet: {src_mac}:{tcp_src_port} -> {dst_mac}:{tcp_dst_port} at switch {dpid}")
        else:
            self.logger.debug(f"Non-TCP packet: {src_mac} -> {dst_mac} at switch {dpid}")

        # Handle broadcast/multicast
        if dst_mac.startswith("ff:ff:ff:ff:ff:ff") or dst_mac.startswith("01:"):
            self.flood_packet(datapath, msg, in_port)
            return

        # Find destination
        dst_dpid, dst_port = self.find_destination(dst_mac)
        if dst_dpid is None:
            self.logger.debug(f"Destination {dst_mac} unknown, flooding")
            self.flood_packet(datapath, msg, in_port)
            return

        # Calculate shortest path
        src_switch = self.dpid_to_node(dpid)
        dst_switch = self.dpid_to_node(dst_dpid)

        # Same switch handling
        if src_switch == dst_switch:
            self.send_packet_out(datapath, msg, dst_port)
            return

        # Find path with TCP-aware ECMP
        if self.ecmp_enabled:
            paths = self.path_finder.find_all_shortest_paths(src_switch, dst_switch)
            chosen_path = self.tcp_aware_select_path_for_flow(
                src_mac, dst_mac, tcp_src_port, tcp_dst_port, paths)
        else:
            chosen_path = self.path_finder.find_shortest_path(src_switch, dst_switch)

        if not chosen_path:
            self.logger.warning(f"No path found from {src_switch} to {dst_switch}")
            self.flood_packet(datapath, msg, in_port)
            return

        self.logger.info(f"Chosen path: {' -> '.join(chosen_path)}")

        # Install flows along the path
        self.install_path_flows(chosen_path, src_mac, dst_mac, tcp_src_port, tcp_dst_port, dst_port)

        # Forward the packet
        next_port = self.get_next_hop_port(dpid, chosen_path)
        if next_port is not None:
            self.send_packet_out(datapath, msg, next_port)
        else:
            self.logger.error(f"Cannot determine next hop port for {dpid} in path {chosen_path}")
            self.flood_packet(datapath, msg, in_port)

    def tcp_aware_select_path_for_flow(self, src_mac, dst_mac, tcp_src_port, tcp_dst_port, paths):
        """TCP-aware path selection for proper parallel connection handling"""
        if not paths:
            return []

        if len(paths) == 1:
            return paths[0]

        # Create enhanced flow key that includes TCP ports
        if tcp_src_port is not None and tcp_dst_port is not None:
            flow_key = f"{src_mac}:{tcp_src_port}-{dst_mac}:{tcp_dst_port}"
        else:
            self.tcp_connection_counter += 1
            flow_key = f"{src_mac}-{dst_mac}-{self.tcp_connection_counter}"

        if flow_key not in self.flow_paths:
            if self.ecmp_enabled:
                chosen_path = paths[self.path_counter % len(paths)]
                self.path_counter += 1
                self.flow_paths[flow_key] = chosen_path
                self.logger.info(f"ECMP selected path #{(self.path_counter-1) % len(paths)} "
                               f"for flow {flow_key}: {' -> '.join(chosen_path)}")
            else:
                chosen_path = paths[0]
                self.flow_paths[flow_key] = chosen_path

        return self.flow_paths[flow_key]

    def install_path_flows(self, path, src_mac, dst_mac, tcp_src_port, tcp_dst_port, dst_port):
        """Install flow rules along the path with TCP port matching"""
        for i, node in enumerate(path):
            dpid = self.node_to_dpid(node)
            if dpid not in self.datapaths:
                continue

            datapath = self.datapaths[dpid]
            parser = datapath.ofproto_parser

            # Determine output port
            if i == len(path) - 1:
                out_port = dst_port
            else:
                next_node = path[i + 1]
                out_port = self.network_graph.get_port_between_nodes(node, next_node)

            if out_port is not None:
                if tcp_src_port is not None and tcp_dst_port is not None:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6,
                        tcp_src=tcp_src_port,
                        tcp_dst=tcp_dst_port,
                        eth_src=src_mac,
                        eth_dst=dst_mac
                    )
                    flow_id = f"{src_mac}:{tcp_src_port}->{dst_mac}:{tcp_dst_port}"
                else:
                    match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                    flow_id = f"{src_mac}->{dst_mac}"

                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 200, match, actions, idle_timeout=15)
                self.logger.info(f"Installed flow at {node}: {flow_id} -> port {out_port}")
            else:
                self.logger.error(f"Cannot determine output port for {node}")

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

    def send_packet_out(self, datapath, msg, out_port):
        """Send packet out specific port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)