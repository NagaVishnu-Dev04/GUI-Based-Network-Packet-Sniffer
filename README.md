# 🚦GUI-Based-Network-Packet-Sniffer
A lightweight, real-time traffic monitoring tool built with Python, Scapy, and Tkinter — designed for beginners, educators, and cybersecurity learners.
# 📚 About the Project
🔍 This project is a **Python-powered GUI tool** that captures and inspects live network packets with real-time visual feedback, offering a lightweight alternative to complex sniffers like **Wireshark**. It solves the problem of inaccessible and overly technical packet sniffers by providing an intuitive interface where users can select interfaces, apply simple protocol filters **(TCP/UDP/ICMP)**, and monitor traffic flow in real time.
<br> <br>
⚙️ Built with **Scapy** for raw packet capture and Tkinter for a **dynamic user interface**, it uses **multithreading** to ensure a smooth, responsive experience even during high traffic.
🎓 Ideal for students, security enthusiasts, and educators, the tool helps users visualize and understand network protocols, detect high traffic spikes, and perform basic diagnostics — all without touching a terminal.
<br><br>
🌐 This open-source solution makes network monitoring more accessible, educational, and efficient in academic, home lab, or entry-level cybersecurity environments. 

# ✨ Features
- **🖥️ Live Packet Capture with Real-Time GUI** <br>
Capture and inspect network packets live using Scapy, presented through a responsive and scrollable Tkinter interface.
<br> <br>
- **🎛️ User-Friendly Interface with Protocol Filters** <br>
Select active network interfaces and apply custom protocol filters (tcp, udp, icmp) directly from the GUI dropdown and input field.
<br><br>
- **📊 Dynamic Traffic Mode Detection** <br>
Automatically classifies traffic into Low 🟢, Medium 🟠, and High 🔴 modes using real-time packet rate analysis (PPS counter).
<br><br>
- **🚨 Automatic High-Traffic Alerts** <br>
Triggers warning popups when traffic exceeds 50 packets/sec, helping identify spikes, DoS attempts, or suspicious network behavior.
<br><br>
- **🔄 Multithreaded Architecture** <br>
Separate threads for sniffing and rate monitoring keep the GUI responsive under heavy traffic, enabling smooth real-time updates.
<br><br>
- **📋 Structured Real-Time Packet Display** <br>
Captured data is shown in a live-updating TreeView with columns for Source IP, Destination IP, Protocol, and Info, with auto-scroll support.
<br><br>
- **🖧 Cross-Platform Compatibility & Admin Check** <br>
Supports both Windows and Linux, with built-in elevation detection and prompts for administrator/root access as required.
<br><br>
- **🔐 Privacy-First Architecture** <br>
No disk logging — all packets are processed in memory only, ensuring confidentiality and safe use in ethical or personal settings.
<br><br>
- **🌐 Interface Discovery with IP Visibility** <br>
Lists all active network interfaces using psutil, displaying associated IPs for intuitive and accurate interface selection.
<br><br>
- **🎓 Designed for Cybersecurity Education** <br>
Ideal for students and learners exploring network protocols, offering an approachable GUI-based alternative to tools like Wireshark.
<br><br>
- **🧩 Modular & Extensible Codebase** <br>
Easily expandable to include future features like machine learning-based anomaly detection, log exporting, or remote sniffing.

# 🛠️ Technology Stack

| Category                | Technology Used                                |
|-------------------------|-----------------------------------------------|
| 🧑‍💻 **Programming Language** | `Python 3.x` |
| 🎨 **GUI Framework**         | `Tkinter` |
| 📦 **Packet Sniffing**       | `Scapy` |
| 🔎 **Interface Discovery**   | `psutil`, `socket`, `platform`, `subprocess` |
| 🔀 **Multithreading**        | `threading`, `queue` |
| ⚙️ **System Utilities**      | `ctypes`, `os`, `sys` |
| 💻 **OS Compatibility**     | `Windows`, `Linux` |
| 🧪 **Future Additions**      | `Scikit-learn`, `CICIDS2017`, `UNSW-NB15` |

# 📁 Project structure

```bash
GUI-Network-Packet-Sniffer/
│
├── 📂 src/
│   ├── 🐍 packet_sniffer.py          # Main application logic
│   ├── 🖼️ gui_interface.py          # Tkinter GUI implementation
│   └── 🔧 utils.py                  # Helper functions (admin checks, etc.)
│
├── 📂 docs/
│   ├── 📜 requirements.txt          # Python dependencies
│   ├── 📘 poster                    
│   └── 🖼️ screenshots/             # Application screenshots
|
├── 🚀 run.py                        # Main entry point
├── 📜 LICENSE
└── 📖 README.md                     # Project documentation
```

# 🚀 Quick Start
