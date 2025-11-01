# run.py
import sys
import os
import tkinter as tk

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now import from vulnscan
from vulnscan.gui import VulnaScanGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnaScanGUI(root)
    root.mainloop()