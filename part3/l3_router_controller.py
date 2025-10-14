#!/usr/bin/env python3
"""
Layer-3 Shortest Path Routing Controller for Part 3.

This controller implements the functionality of a Layer-3 router using OpenFlow.
It reads a network configuration, responds to ARP requests for gateway IPs,
and installs forwarding rules for IP packets based on the shortest path
calculated by Dijkstra's algorithm. At each hop, it rewrites the Ethernet
headers (source/destination MAC) and decrements the IP packet's TTL.
"""

import json
import os
import heapq

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types

class L3RouterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3RouterController, self).__init__(*args, **kwargs)
        self.logger.info("Initializing L3 Router Controller")

        # Data structures to hold the network topology information
        self.ip_to_mac = {}
        self.ip_to_location = {}  # Format: {ip: (switch_name, port_to_host)}
        self.port_map = {}        # Format: {switch_name: {neighbor_name: port_num}}
        self.graph = {}           # Adjacency list for Dijkstra: {switch: {neighbor: cost}}
        self.datapaths = {}       # Store datapath objects: {dpid: datapath}

        # Load network configuration from JSON
        self._load_config('p3_config.json')

    def _load_config(self, config_path_str):
        """
        Loads and parses the network configuration file.
        This builds the controller's view of the network, including IP/MAC mappings,
        switch port connections, and the weighted graph for path calculation.
        """
        try:
            full_path = os.path.join(os.path.dirname(__file__), config_path_str)
            with open(full_path, 'r') as f:
                config = json.load(f)
            self.logger.info("Configuration loaded successfully from %s", config_path_str)
        except Exception as e:
            self.logger.error("Failed to load config file: %s", e)
            return

        # Static port mapping based on the p3_topo-2.py script
        self.port_map = {
            's1': {'h1': 1, 's2': 2, 's4': 3},
            's2': {'s1': 1, 's3': 2},
            's3': {'s2': 1, 's6': 2},
            's4': {'s1': 1, 's5': 2},
            's5': {'s4': 1, 's6': 2},  # BUG FIX: Corrected port mapping for s5
            's6': {'s3': 1, 's5': 2, 'h2': 3},
        }

        # Build IP-to-MAC mapping from hosts and switch interfaces
        for host in config['hosts']:
            self.ip_to_mac[host['ip']] = host['mac']
            self.ip_to_location[host['ip']] = (host['switch'], self.port_map[host['switch']][host['name']])

        for switch in config['switches']:
            switch_name = switch['name']
            self.graph.setdefault(switch_name, {})
            # Note: There's a typo "intesfaces" and "neighbos" in the provided config file
            interfaces_key = "intesfaces" if "intesfaces" in switch else "interfaces"
            for iface in switch[interfaces_key]:
                self.ip_to_mac[iface['ip']] = iface['mac']

        # Build graph for Dijkstra's algorithm from links
        # Note: There's a typo "ssc" in the provided config file
        for link in config['links']:
            src_switch = link.get('src', link.get('ssc')) # Handle typo 'ssc'
            dst_switch = link['dst']
            cost = link['cost']
            self.graph.setdefault(src_switch, {})[dst_switch] = cost
            self.graph.setdefault(dst_switch, {})[src_switch] = cost

        self.logger.info("Network model built from configuration.")

    def _get_interface_ip(self, switch_name, port_num):
        """Find the IP address of a switch interface given the port number."""
        neighbor_name = None
        for neighbor, port in self.port_map.get(switch_name, {}).items():
            if port == port_num:
                neighbor_name = neighbor
                break
        if not neighbor_name:
            return None

        config_path = os.path.join(os.path.dirname(__file__), 'p3_config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        for switch in config['switches']:
            if switch['name'] == switch_name:
                interfaces_key = "intesfaces" if "intesfaces" in switch else "interfaces"
                neighbor_key = "neighbos" if "neighbos" in switch[interfaces_key][0] else "neighbor"
                for iface in switch[interfaces_key]:
                    if iface[neighbor_key] == neighbor_name:
                        return iface['ip']
        return None

    def _find_shortest_path(self, src_switch, dst_switch):
        """Calculates the shortest path using Dijkstra's algorithm."""
        distances = {node: float('infinity') for node in self.graph}
        previous_nodes = {node: None for node in self.graph}
        distances[src_switch] = 0
        pq = [(0, src_switch)]

        while pq:
            current_distance, current_node = heapq.heappop(pq)

            if current_distance > distances[current_node]:
                continue

            for neighbor, weight in self.graph.get(current_node, {}).items():
                distance = current_distance + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous_nodes[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))

        path = []
        current = dst_switch
        while current is not None:
            path.insert(0, current)
            current = previous_nodes[current]

        return path if path and path[0] == src_switch else []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connections and install table-miss flow entry."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch DPID=%d connected and table-miss entry installed.", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main packet handler, dispatches to ARP or IP handlers."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if not eth_pkt:
            return

        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(datapath, in_port, pkt)
        elif eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
            self._handle_ip(datapath, in_port, pkt)

    def _handle_arp(self, datapath, port, pkt):
        """Handles ARP requests for gateway MAC addresses."""
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        requested_ip = arp_pkt.dst_ip
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        target_mac = self.ip_to_mac.get(requested_ip)
        if not target_mac:
            self.logger.warning("ARP request for unknown IP %s", requested_ip)
            return

        self.logger.info("Received ARP request for gateway %s from %s. Replying.", requested_ip, src_ip)
        
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                         dst=src_mac,
                                         src=target_mac))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                               src_mac=target_mac,
                               src_ip=requested_ip,
                               dst_mac=src_mac,
                               dst_ip=src_ip))
        
        self._send_packet(datapath, port, p)

    def _handle_ip(self, datapath, in_port, pkt):
        """Handles IP packets by calculating paths and installing L3 flow rules."""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        self.logger.info("Received IP packet from %s to %s at switch %d", src_ip, dst_ip, dpid)

        src_switch = f's{dpid}'
        dst_location = self.ip_to_location.get(dst_ip)
        if not dst_location:
            self.logger.warning("No location found for destination IP %s. Dropping packet.", dst_ip)
            return
        dst_switch = dst_location[0]

        path = self._find_shortest_path(src_switch, dst_switch)
        if not path:
            self.logger.error("No path found from %s to %s.", src_switch, dst_switch)
            return
        
        self.logger.info("Shortest path found: %s", " -> ".join(path))

        # BUG FIX: Handle single-hop case (source and destination on same switch)
        if len(path) == 1:
            self.logger.info("Destination is on the same switch. Installing host-facing flow.")
            final_switch_name = path[0]
            final_dpid = int(final_switch_name[1:])
            final_datapath = self.datapaths[final_dpid]
            parser = final_datapath.ofproto_parser
            
            host_port = self.ip_to_location[dst_ip][1]
            gateway_ip = self._get_interface_ip(final_switch_name, host_port)

            if gateway_ip is None:
                self.logger.error(f"Could not find gateway IP for {final_switch_name} port {host_port}")
                return

            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            actions = [
                parser.OFPActionSetField(eth_src=self.ip_to_mac[gateway_ip]),
                parser.OFPActionSetField(eth_dst=self.ip_to_mac[dst_ip]),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(host_port)
            ]
            self.add_flow(final_datapath, 10, match, actions, idle_timeout=60)

            # Send this packet out to the host
            ofproto = final_datapath.ofproto
            out = parser.OFPPacketOut(datapath=final_datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=pkt.data)
            final_datapath.send_msg(out)
            return

        # --- Multi-hop logic ---
        # Install flow rules for all inter-switch hops
        for i in range(len(path) - 1):
            current_s, next_s = path[i], path[i+1]
            out_port = self.port_map[current_s][next_s]
            
            src_mac_for_hop = self.ip_to_mac[self._get_interface_ip(current_s, out_port)]
            next_hop_in_port = self.port_map[next_s][current_s]
            dst_mac_for_hop = self.ip_to_mac[self._get_interface_ip(next_s, next_hop_in_port)]

            current_dpid = int(current_s[1:])
            current_datapath = self.datapaths[current_dpid]
            parser = current_datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
            actions = [
                parser.OFPActionSetField(eth_src=src_mac_for_hop),
                parser.OFPActionSetField(eth_dst=dst_mac_for_hop),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(out_port)
            ]
            self.add_flow(current_datapath, 10, match, actions, idle_timeout=60)
            self.logger.info(f"Installed L3 flow on {current_s}: match(dst_ip={dst_ip}) -> actions(set_macs, dec_ttl, output:{out_port})")

        # Install final flow rule on the last switch to reach the host
        final_switch_name = path[-1]
        final_dpid = int(final_switch_name[1:])
        final_datapath = self.datapaths[final_dpid]
        parser = final_datapath.ofproto_parser
        host_port = self.ip_to_location[dst_ip][1]
        gateway_ip = self._get_interface_ip(final_switch_name, host_port)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
        actions = [
            parser.OFPActionSetField(eth_src=self.ip_to_mac[gateway_ip]),
            parser.OFPActionSetField(eth_dst=self.ip_to_mac[dst_ip]),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(host_port)
        ]
        self.add_flow(final_datapath, 10, match, actions, idle_timeout=60)
        self.logger.info(f"Installed final L3 flow on {final_switch_name}: match(dst_ip={dst_ip}) -> actions(set_macs, dec_ttl, output:{host_port})")

        # Send the initial packet out using the first hop's logic
        out_port_first_hop = self.port_map[path[0]][path[1]]
        out_ip_first_hop = self._get_interface_ip(path[0], out_port_first_hop)
        in_port_second_hop = self.port_map[path[1]][path[0]]
        in_ip_second_hop = self._get_interface_ip(path[1], in_port_second_hop)
        
        actions_for_packetout = [
            parser.OFPActionSetField(eth_src=self.ip_to_mac[out_ip_first_hop]),
            parser.OFPActionSetField(eth_dst=self.ip_to_mac[in_ip_second_hop]),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port_first_hop)
        ]
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions_for_packetout, data=pkt.data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        """Helper function to add a flow entry to a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        """Helper function to send a packet out a specific switch port."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)