# === src/packet_sniffer.py ===
import os
import ctypes
import sys
import tkinter as tk
from gui_interface import PacketSnifferGUI

if __name__ == "__main__":
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
