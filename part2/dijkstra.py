#!/usr/bin/env python3
"""
Dijkstra's Algorithm Implementation
For shortest path computation with ECMP support
"""

import heapq
from collections import defaultdict

class DijkstraPathFinder:
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

    def print_path_info(self, source, destination):
        """Print information about shortest paths"""
        paths = self.find_all_shortest_paths(source, destination)

        print(f"\nShortest paths from {source} to {destination}:")
        for i, path in enumerate(paths):
            cost = self._calculate_path_cost(path)
            print(f"Path {i+1}: {' -> '.join(path)} (cost: {cost})")

        return paths

    def _calculate_path_cost(self, path):
        """Calculate total cost of a path"""
        total_cost = 0
        for i in range(len(path) - 1):
            total_cost += self.graph.get_weight(path[i], path[i+1])
        return total_cost
