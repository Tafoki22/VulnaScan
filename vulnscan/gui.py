# vulnscan/gui.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
from .core import VulnaScanner

class VulnaScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnaScan - Web Vulnerability Scanner")
        self.root.geometry("800x600")
        self.scanner = VulnaScanner()

        # Show ethical disclaimer on startup
        self.show_disclaimer()

        # URL Input
        tk.Label(root, text="Enter Target URL:").pack(pady=(10, 0))
        self.url_entry = tk.Entry(root, width=70)
        self.url_entry.pack(pady=5)
        self.url_entry.bind("<Return>", lambda e: self.start_scan())

        # Scan Button
        self.scan_btn = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(pady=5)

        # Log Output
        tk.Label(root, text="Scan Log:").pack(anchor="w", padx=10, pady=(10, 0))
        self.log_text = scrolledtext.ScrolledText(root, height=15, state="disabled")
        self.log_text.pack(padx=10, fill="both", expand=True)

        # History Button
        self.history_btn = tk.Button(root, text="View Scan History", command=self.show_history)
        self.history_btn.pack(pady=10)

    def show_disclaimer(self):
        disclaimer = (
            "⚠️ ETHICAL USE ONLY ⚠️\n\n"
            "VulnaScan is for educational and authorized security testing purposes only.\n\n"
            "By using this tool, you agree to scan ONLY:\n"
            "• Systems you own\n"
            "• Systems you have explicit written permission to test\n\n"
            "Unauthorized scanning may violate laws like the Computer Fraud and Abuse Act (CFAA).\n\n"
            "Proceed responsibly."
        )
        messagebox.showinfo("VulnaScan - Ethical Disclaimer", disclaimer)

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see("end")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        self.scan_btn.config(state="disabled")
        self.log(f"[+] Starting scan for: {url}")
        try:
            result = self.scanner.scan(url)
            self.log("[✓] Scan completed!")
            for key, value in result.items():
                if key not in ["url", "timestamp"]:
                    self.log(f"  {key}: {value}")
        except Exception as e:
            self.log(f"[!] Scan failed: {e}")
        finally:
            self.scan_btn.config(state="normal")

    def show_history(self):
        try:
            with open(self.scanner.results_file, "r") as f:
                history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showinfo("History", "No scan history found.")
            return

        if not history:
            messagebox.showinfo("History", "No scans recorded.")
            return

        # Create history window
        hist_window = tk.Toplevel(self.root)
        hist_window.title("Scan History")
        hist_window.geometry("900x500")

        cols = list(history[0].keys())
        tree = ttk.Treeview(hist_window, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=120)

        for entry in history:
            values = [str(entry.get(col, "")) for col in cols]
            tree.insert("", "end", values=values)

        tree.pack(fill="both", expand=True)