# NETWORK
NETMIKO SCRIPTS 

FROM CHAT GPT 

# Netmiko VLAN Collector

This Python script connects to all Cisco switches within a given subnet, collects **all VLANs** (with names), and exports the data to a **CSV report**.  
If authentication or connectivity fails for any device, it **skips silently** and continues with the rest.

---

## 🚀 Features

- Automatically detects and connects to all switches within a specified subnet.  
- Collects **all VLANs** across reachable switches (not just shared ones).  
- Merges VLAN information and lists which switches each VLAN appears on.  
- Exports results to a timestamped CSV file.  
- Silently skips switches with login or connection failures (no interruptions).  
- Supports Cisco IOS devices by default — can be adapted for NX-OS, EOS, etc.

---

## 📦 Requirements

- Python 3.8+
- [Netmiko](https://pypi.org/project/netmiko/)
- `switches.txt` file listing switch IP addresses

---

## 🧰 Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/netmiko-vlan-collector.git
   cd netmiko-vlan-collector
