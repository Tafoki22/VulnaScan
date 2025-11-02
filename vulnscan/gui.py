# vulnscan/gui.py
import customtkinter as ctk
from tkinter import messagebox, ttk
import json
import os
from .core import VulnaScanner

# Set appearance mode and theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class VulnaScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnaScan - Ethical Web Vulnerability Scanner")
        self.root.geometry("950x750")
        self.root.minsize(800, 600)
        self.scanner = VulnaScanner()

        # Show ethical disclaimer on first launch
        self.show_disclaimer()

        # URL Input Section
        url_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        url_frame.pack(pady=(15, 10), padx=20, fill="x")

        ctk.CTkLabel(
            url_frame,
            text="🔍 Enter Target URL:",
            font=("Arial", 14, "bold"),
            text_color=("gray10", "gray90")
        ).pack(anchor="w")

        self.url_entry = ctk.CTkEntry(
            url_frame,
            placeholder_text="e.g., example.com",
            height=36,
            font=("Arial", 12),
            corner_radius=8
        )
        self.url_entry.pack(fill="x", pady=(5, 0))
        self.url_entry.bind("<Return>", lambda e: self.start_scan())

        # Button Row
        button_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        button_frame.pack(pady=10, padx=20, fill="x")

        self.scan_btn = ctk.CTkButton(
            button_frame,
            text="🚀 Start Scan",
            command=self.start_scan,
            height=36,
            font=("Arial", 12, "bold"),
            corner_radius=8,
            fg_color="#007BFF",
            hover_color="#0056b3"
        )
        self.scan_btn.pack(side="left", padx=(0, 10))

        self.tips_btn = ctk.CTkButton(
            button_frame,
            text="💡 Show Mitigation Tips",
            command=self.show_mitigation_tips,
            height=36,
            corner_radius=8,
            fg_color="#28a745",
            hover_color="#218838"
        )
        self.tips_btn.pack(side="left", padx=10)

        self.history_btn = ctk.CTkButton(
            button_frame,
            text="📜 View History",
            command=self.show_history,
            height=36,
            corner_radius=8,
            fg_color="#ffc107",
            hover_color="#e0a800",
            text_color="black"
        )
        self.history_btn.pack(side="left", padx=10)

        self.export_btn = ctk.CTkButton(
            button_frame,
            text="📤 Export to CSV",
            command=self.export_to_csv,
            height=36,
            corner_radius=8,
            fg_color="#dc3545",
            hover_color="#c82333"
        )
        self.export_btn.pack(side="left", padx=(10, 0))

        # Scan Log Panel
        ctk.CTkLabel(
            self.root,
            text="📋 Scan Log:",
            font=("Arial", 13, "bold"),
            text_color=("gray10", "gray90"),
            anchor="w"
        ).pack(padx=20, pady=(15, 5), anchor="w")

        self.log_text = ctk.CTkTextbox(
            self.root,
            height=180,
            wrap="word",
            font=("Consolas", 11),
            corner_radius=8,
            fg_color=("gray90", "gray15"),
            text_color=("gray10", "gray90")
        )
        self.log_text.pack(padx=20, fill="both", expand=False)

        # Mitigation Tips Panel
        ctk.CTkLabel(
            self.root,
            text="🛡️ Mitigation Guidance (Based on Latest Scan):",
            font=("Arial", 13, "bold"),
            text_color=("gray10", "gray90"),
            anchor="w"
        ).pack(padx=20, pady=(15, 5), anchor="w")

        self.tips_text = ctk.CTkTextbox(
            self.root,
            height=160,
            wrap="word",
            font=("Arial", 11),
            corner_radius=8,
            fg_color=("gray90", "gray15"),
            text_color=("gray10", "gray90")
        )
        self.tips_text.pack(padx=20, fill="both", expand=False)

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
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        self.scan_btn.configure(state="disabled")
        self.log(f"[+] Starting scan for: {url}")
        try:
            result = self.scanner.scan(url)
            self.log("[✓] Scan completed!")

            tips = self.scanner.get_mitigation_tips(result)
            self.tips_text.delete("0.0", "end")
            if tips:
                for tip in tips:
                    self.tips_text.insert("end", tip + "\n\n")
            else:
                self.tips_text.insert("end", "• No critical issues found. Keep up the good work!\n")
        except Exception as e:
            self.log(f"[!] Scan failed: {e}")
        finally:
            self.scan_btn.configure(state="normal")

    def show_mitigation_tips(self):
        if not self.scanner.scan_history:
            messagebox.showinfo("Tips", "No scan results yet.")
            return
        latest = self.scanner.scan_history[-1]
        tips = self.scanner.get_mitigation_tips(latest)
        self.tips_text.delete("0.0", "end")
        if tips:
            for tip in tips:
                self.tips_text.insert("end", tip + "\n\n")
        else:
            self.tips_text.insert("end", "• No critical issues found. Keep up the good work!\n")

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
        hist_window = ctk.CTkToplevel(self.root)
        hist_window.title("📜 Scan History")
        hist_window.geometry("950x500")
        hist_window.minsize(700, 400)

        ctk.CTkLabel(
            hist_window,
            text="Recent Scan Results",
            font=("Arial", 16, "bold"),
            text_color=("gray10", "gray90")
        ).pack(pady=(10, 5))

        # Frame for table
        tree_frame = ctk.CTkFrame(hist_window, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=15, pady=10)

        # Style Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="#f0f0f0",
                        foreground="black",
                        rowheight=25,
                        fieldbackground="#f0f0f0",
                        font=("Arial", 10))
        style.map("Treeview",
                  background=[("selected", "#0078d7")],
                  foreground=[("selected", "white")])

        cols = list(history[0].keys())
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", style="Treeview")

        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=120, minwidth=100, stretch=True)

        for entry in history:
            values = [str(entry.get(col, "")) for col in cols]
            tree.insert("", "end", values=values)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

    def export_to_csv(self):
        success = self.scanner.export_to_csv()
        if success:
            csv_path = "vulnscan/data/scan_history.csv"
            abs_path = os.path.abspath(csv_path)
            messagebox.showinfo("Export Success", f"Scan history saved to:\n{abs_path}")
        else:
            messagebox.showwarning("Export Failed", "No scan history to export, or an error occurred.")