import socket
import threading
import ipaddress

TARGET_PORTS = [22, 445, 3389, 139, 5985]
TIMEOUT = 1

# ===================== RISK MODEL =====================

PORT_WEIGHTS = {
    445: 3,     # SMB
    3389: 4,    # RDP
    22: 2,      # SSH
    139: 2,     # NetBIOS
    5985: 3     # WinRM
}

# Mitigation recommendations per service
PORT_MITIGATIONS = {
    22:  "Restrict SSH (firewall allow-list, key-only login, disable password auth)",
    445: "Disable SMB if not required or block via firewall; apply patches",
    3389:"Restrict RDP to VPN/internal network and enable MFA",
    139: "Disable NetBIOS if not required",
    5985:"Restrict WinRM to admin hosts only; use HTTPS and strong authentication"
}

scan_results = {}

# ===================== SCANNING ENGINE =====================

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            print(f"[+] {target_ip} → {port} OPEN")
            scan_results[target_ip].append(port)

        sock.close()

    except:
        pass


def scan_host(target_ip):
    scan_results[target_ip] = []

    print(f"\nScanning host: {target_ip}")

    threads = []

    for port in TARGET_PORTS:
        thread = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


def scan_subnet(subnet):
    network = ipaddress.ip_network(subnet, strict=False)

    for ip in network.hosts():
        scan_host(str(ip))


# ===================== TRUST GRAPH =====================

def build_trust_graph(scan_results):

    graph = {}

    for source_host in scan_results:
        graph[source_host] = []

        for target_host in scan_results:
            if source_host == target_host:
                continue

            target_ports = scan_results[target_host]

            if len(target_ports) > 0:
                max_weight = max([PORT_WEIGHTS.get(p, 1) for p in target_ports])
                graph[source_host].append((target_host, max_weight))

    return graph


# ===================== PIVOT ENGINE =====================

def generate_attack_paths(graph, start_node):

    paths = []

    def dfs(current_node, path, total_risk, visited):
        visited.add(current_node)
        path.append(current_node)

        for neighbor, weight in graph[current_node]:
            if neighbor not in visited:
                dfs(neighbor, path.copy(), total_risk + weight, visited.copy())

        if len(path) > 1:
            paths.append((path, total_risk))

    dfs(start_node, [], 0, set())

    return paths


# ===================== MITIGATION ENGINE =====================

def generate_mitigations(best_path, scan_results):

    print("\n Recommended Mitigation Actions:\n")

    for host in best_path[1:]:  # Skip compromised entry host

        ports = scan_results.get(host, [])

        if not ports:
            continue

        print(f"Host: {host}")

        for port in ports:

            recommendation = PORT_MITIGATIONS.get(
                port,
                "Restrict access to this service via firewall"
            )

            print(f" • Port {port}: {recommendation}")

        print()


# ===================== VISUALIZATION =====================

def visualize_graph(graph, start_node, best_path):
    import networkx as nx
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.lines as mlines

    G = nx.DiGraph()

    for src in graph:
        for dst, weight in graph[src]:
            G.add_edge(src, dst, weight=weight)

    pos = nx.spring_layout(G, seed=42, k=1.5)

    plt.figure(figsize=(10, 8))

    # Node colors
    node_colors = []
    for node in G.nodes():
        if node == start_node:
            node_colors.append("red")
        else:
            node_colors.append("skyblue")

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=2500)

    # Normal edges
    nx.draw_networkx_edges(G, pos, arrows=True)

    # Highlight best path
    if best_path:
        path_edges = list(zip(best_path[:-1], best_path[1:]))

        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=path_edges,
            edge_color="red",
            width=4,
            arrows=True
        )

    # Node labels
    label_pos = {node: (x, y + 0.08) for node, (x, y) in pos.items()}
    nx.draw_networkx_labels(G, label_pos, font_size=10)

    # Edge labels (weights)
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        label_pos=0.5,
        font_size=10
    )

    # ===================== LEGEND =====================

    compromised_patch = mpatches.Patch(color='red', label='Compromised Host')
    other_patch = mpatches.Patch(color='skyblue', label='Other Hosts')

    best_path_line = mlines.Line2D(
        [], [], color='red', linewidth=4, label='Highest-Risk Path'
    )

    normal_line = mlines.Line2D(
        [], [], color='black', linewidth=1, label='Other Pivot Paths'
    )

    plt.legend(
        handles=[compromised_patch, other_patch, best_path_line, normal_line],
        loc='upper left',
        bbox_to_anchor=(1.02, 1),
        borderaxespad=0
    )

    plt.tight_layout(rect=[0, 0, 0.8, 1])

    plt.title("Lateral Movement Trust Graph")
    plt.axis("off")
    plt.show()


# ===================== MAIN =====================

if __name__ == "__main__":

    subnet_input = input("Enter subnet (e.g., 192.168.56.0/24): ")

    scan_subnet(subnet_input)

    scan_results_filtered = {
        host: ports for host, ports in scan_results.items() if len(ports) > 0
    }

    print("\nFinal Network Map:")
    print(scan_results_filtered)

    trust_graph = build_trust_graph(scan_results_filtered)

    print("\nGenerated Trust Graph:")
    for node in trust_graph:
        print(f"{node} → {trust_graph[node]}")

    if len(trust_graph) == 0:
        print("\nNo pivotable hosts found.")
        exit()

    start_host = list(trust_graph.keys())[0]

    print(f"\nSimulating compromise of: {start_host}")

    attack_paths = generate_attack_paths(trust_graph, start_host)

    attack_paths.sort(key=lambda x: x[1], reverse=True)

    print("\nGenerated Attack Paths (Ranked):")

    rank = 1

    for path, risk in attack_paths:

        if risk >= 6:
            severity = "HIGH"
        elif risk >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(f"{rank}) " + " → ".join(path))
        print(f"   Risk Score: {risk} ({severity})\n")

        rank += 1

    best_path = attack_paths[0][0] if attack_paths else []

    visualize_graph(trust_graph, start_host, best_path)

    generate_mitigations(best_path, scan_results_filtered)