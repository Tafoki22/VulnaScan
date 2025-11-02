import customtkinter as ctk
from vulnscan.gui import VulnaScanGUI

if __name__ == "__main__":
    root = ctk.CTk()
    app = VulnaScanGUI(root)
    root.mainloop()