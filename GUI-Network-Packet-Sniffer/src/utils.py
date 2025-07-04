# === src/utils.py ===
import os
import ctypes

def check_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except:
        return False
