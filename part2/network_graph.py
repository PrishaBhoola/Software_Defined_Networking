#!/usr/bin/env python3
"""
FIXED Network Graph Utilities
Correct port mappings based on actual topology creation order
"""

class NetworkGraph:
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
                weight = self.weight_matrix[i][j]

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
