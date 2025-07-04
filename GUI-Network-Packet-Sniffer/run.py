# === run.py ===
import os
import sys

# Add the src/ directory to Python path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from packet_sniffer import *

# This will execute packet_sniffer.py's main block (Tkinter GUI will launch)
