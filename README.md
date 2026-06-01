Lateral Movement Risk Analyzer

A graph-based cybersecurity tool that models how an attacker can spread inside an internal network after an initial compromise, ranks attack paths by risk, visualizes propagation, and provides mitigation strategies.

 Overview

Traditional network scanners identify open ports and services but do not analyze how attackers can move laterally across systems.

This project extends basic network scanning with:

- Attack path modeling  
- Risk-based prioritization  
- Visual representation of attack propagation  
- Defensive mitigation recommendations  


 Key Features

- Subnet Scanning  
  Detects hosts exposing remote-access services (SSH, SMB, RDP, etc.)

-  Trust Graph Construction  
  Models network as nodes (hosts) and edges (pivot paths)

- Risk-Based Weighting  
  Assigns severity scores based on exposed services

-  Attack Path Simulation  
  Generates multi-hop lateral movement paths

- Path Ranking  
  Prioritizes most dangerous attack chains

-  Graph Visualization  
  Displays attack flow with highlighted high-risk path

-  Mitigation Engine  
  Suggests security controls to break attack paths


How It Works

Input Subnet  
       ↓  
Network Scan  
       ↓  
Pivot Host Identification  
       ↓  
Trust Graph Construction  
       ↓  
Risk Assignment  
       ↓  
Attack Path Simulation (DFS)  
       ↓  
Path Ranking  
       ↓  
Visualization  
       ↓  
Mitigation Recommendations  


Tech Stack

- Python 3  
- socket (network scanning)  
- threading (parallel scanning)  
- ipaddress (subnet handling)  
- networkx (graph modeling)  
- matplotlib (visualization)  


Installation

git clone https://github.com/shreeyaas12/LATERAL-MOVEMENT-ANALYZER.git  
cd LATERAL-MOVEMENT-ANALYZER 
pip install networkx matplotlib  


 Usage

python main.py  

Enter subnet (example):  
192.168.56.0/24  


 Example Output

Attack Paths:

1) 192.168.56.101 → 192.168.56.102 → 192.168.56.103  
   Risk Score: 5 (MEDIUM)  

2) 192.168.56.101 → 192.168.56.103  
   Risk Score: 3 (LOW)  


Visualization shows:

- Compromised host  
- Other hosts  
- Pivot paths  
- Highest-risk attack path  
- Risk values on edges  


Mitigation Recommendations:

Host: 192.168.56.102  
• Port 445: Disable SMB or restrict via firewall  

Host: 192.168.56.103  
• Port 22: Restrict SSH access  


 Use Cases

- Internal network security assessment  
- Breach impact analysis  
- Lateral movement research  
- Cybersecurity labs and education  
- Defensive strategy planning  


 Novelty

Traditional scanners:

- Only show open ports  
- Do not model attack flow  

This project:

- Models attacker movement  
- Ranks attack paths by risk  
- Visualizes propagation  
- Suggests mitigation actions  



 Security Concept

Focus: Lateral Movement Analysis  
Understanding how attackers pivot between systems after compromise.



 Limitations

- Works within reachable/internal network  
- Uses basic TCP connect scanning  
- Does not perform exploitation  
- No credential analysis  


 Future Enhancements

- Cross-subnet analysis  
- Credential reuse modeling  
- Integration with vulnerability scanners  
- GUI dashboard  
- Automated report generation  


 Author

Shakthivel Rajesh  
Cybersecurity Enthusiast | Network Security  



 License

Educational and research purposes only.



## 💡 Summary

Converts network scan data into a visual, risk-ranked model of attacker movement inside a network.
