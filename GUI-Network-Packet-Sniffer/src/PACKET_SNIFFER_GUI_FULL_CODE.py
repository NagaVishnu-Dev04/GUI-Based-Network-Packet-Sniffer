import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import platform
import os
import ctypes
import sys
import psutil
import socket
import threading
import time
import queue

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer with Traffic Modes")
        self.root.geometry("850x600")
        self.running = False
        self.packet_queue = queue.Queue()
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Select Network Interface:").grid(row=0, column=0, sticky=tk.W)
        self.interface_combo = ttk.Combobox(main_frame, state="readonly")
        self.interface_combo.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        self.refresh_button = ttk.Button(main_frame, text="Refresh", command=self.load_interfaces)
        self.refresh_button.grid(row=0, column=2, padx=5)

        ttk.Label(main_frame, text="Filter (e.g., tcp, udp, icmp):").grid(row=1, column=0, sticky=tk.W)
        self.filter_entry = ttk.Entry(main_frame)
        self.filter_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        self.filter_entry.insert(0, "tcp")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)

        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(main_frame, text="Captured Packets:").grid(row=3, column=0, sticky=tk.W)

        self.packet_tree = ttk.Treeview(main_frame, columns=("src", "dst", "protocol", "info"), show="headings")
        self.packet_tree.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW)

        self.packet_tree.heading("src", text="Source")
        self.packet_tree.heading("dst", text="Destination")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("info", text="Info")

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        scrollbar.grid(row=4, column=3, sticky=tk.NS)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)

        self.status_var = tk.StringVar()
        self.status_var.set("🟡 Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=3, sticky=tk.W)

        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        self.load_interfaces()

    def get_network_interfaces(self):
        interfaces = []
        try:
            net_if_addrs = psutil.net_if_addrs()
            for iface_name, iface_addrs in net_if_addrs.items():
                ip_address = ""
                for addr in iface_addrs:
                    if addr.family == socket.AF_INET:
                        ip_address = addr.address
                        break
                interfaces.append((iface_name, ip_address))
        except:
            pass
        return interfaces or [(iface, '') for iface in get_if_list()]

    def load_interfaces(self):
        interfaces = self.get_network_interfaces()
        if not interfaces:
            messagebox.showwarning("Warning", "No network interfaces found.")
            self.status_var.set("❌ No interfaces found.")
            return
        interface_names = [f"{name} ({desc})" if desc else name for name, desc in interfaces]
        self.interface_combo['values'] = interface_names
        self.interface_combo.current(0)
        self.status_var.set(f"✅ {len(interfaces)} interfaces loaded.")

    def packet_callback(self, packet):
        self.packet_queue.put(1)
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                proto_name = proto_map.get(proto, str(proto))
                info = ""

                if packet.haslayer(TCP):
                    info = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    info = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
                elif packet.haslayer(ICMP):
                    info = "ICMP Packet"

                self.root.after(0, lambda: self.packet_tree.insert("", tk.END, values=(src_ip, dst_ip, proto_name, info)))
                self.root.after(0, lambda: self.packet_tree.yview_moveto(1))
        except Exception as e:
            print(f"Error: {e}")

    def start_sniffing(self):
        if not self.check_admin():
            return
        if not self.interface_combo.get():
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.status_var.set("🔵 Sniffing started...")

        iface = self.interface_combo.get().split(" (")[0]
        filter_str = self.filter_entry.get()

        threading.Thread(target=self.run_sniffer, args=(iface, filter_str), daemon=True).start()
        threading.Thread(target=self.monitor_traffic_rate, daemon=True).start()

    def run_sniffer(self, iface, filter_str):
        try:
            sniff(iface=iface, prn=self.packet_callback, filter=filter_str, store=False)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Sniffing Error", str(e)))

    def monitor_traffic_rate(self):
        while self.running:
            start = time.time()
            count = 0
            try:
                while time.time() - start < 1:
                    self.packet_queue.get(timeout=1)
                    count += 1
            except:
                pass

            if not self.running:
                break

            mode = "🟢 Low"
            if count > 50:
                mode = "🔴 High"
                self.root.after(0, lambda: messagebox.showwarning("High Traffic Alert", f"🚨 High traffic detected: {count} packets/sec"))
            elif count > 20:
                mode = "🟠 Medium"

            self.root.after(0, lambda m=mode, c=count: self.status_var.set(f"{m} Traffic - {c} pps"))

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("🟡 Sniffing stopped")

    def check_admin(self):
        try:
            if os.name == 'nt':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.getuid() == 0
        except:
            return False

if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
