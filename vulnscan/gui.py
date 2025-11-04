import customtkinter as ctk
from tkinter import messagebox
import os
import json
import re
from .core import VulnaScanner


class VulnaScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnaScan - Ethical Web Vulnerability Scanner")
        self.root.geometry("950x780")
        self.root.minsize(800, 650)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.scanner = VulnaScanner()
        self.show_disclaimer()
        self.setup_gui()
        self.loading = False
        self.loading_dots = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.dot_index = 0

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

    def setup_gui(self):
        self.root.configure(fg_color="#0f0f0f")

        # === WATERMARK LABEL (behind everything) ===
        self.watermark = ctk.CTkLabel(
        self.root,
        text="Ethical Hacking • Cyber Security • Authorized Use Only",
        font=("Arial", 28, "bold"),
        text_color="#1a1a1a",  # Very light gray on dark bg
        fg_color="transparent"
        )
        # Place behind all content, centered and rotated visually via layout
        self.watermark.place(relx=0.5, rely=0.5, anchor="center")
        self.watermark.lower()  # Send to back

        # === Title (on top of watermark) ===
        title = ctk.CTkLabel(
        self.root, text="🔍🛡️ VulnaScan",
        font=("Consolas", 28, "bold"),
        text_color="#00ffff"
        )
        title.pack(pady=(10, 5))

        # === URL Input ===
        url_frame = ctk.CTkFrame(self.root, fg_color="#1a1a1a", corner_radius=10)
        url_frame.pack(pady=(0, 10), padx=30, fill="x")
        ctk.CTkLabel(url_frame, text="🌐 Enter Target URL:", font=("Consolas", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 0))
        self.url_entry = ctk.CTkEntry(url_frame, placeholder_text="e.g., example.com", height=40)
        self.url_entry.pack(fill="x", padx=15, pady=(5, 15))
        self.url_entry.bind("<Return>", lambda e: self.start_scan())

        # === Buttons ===
        btn_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_frame.pack(pady=10, padx=30, fill="x")

        self.scan_btn = ctk.CTkButton(btn_frame, text="🚀 Start Scan", command=self.start_scan, height=40, fg_color="#b22222")
        self.scan_btn.pack(side="left", padx=(0, 10))

        self.copy_btn = ctk.CTkButton(btn_frame, text="📋 Copy Results", command=self.copy_results, height=40, fg_color="#1e90ff")
        self.copy_btn.pack(side="left", padx=10)

        self.export_btn = ctk.CTkButton(btn_frame, text="📤 Export to CSV", command=self.export_to_csv, height=40, fg_color="#8a6bbf")
        self.export_btn.pack(side="right")

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self.root, height=8, corner_radius=4, progress_color="#ff3333")
        self.progress.set(0)
        self.progress.pack(padx=30, fill="x", pady=(0, 10))

        # Tabs
        self.tabview = ctk.CTkTabview(self.root, height=460)
        self.tabview.pack(padx=30, pady=(0, 20), fill="both", expand=True)
        self.tabview.add("📋 Scan Log")
        self.tabview.add("💡 Mitigation Tips")
        self.tabview.add("📜 Scan History")

        self.log_text = ctk.CTkTextbox(self.tabview.tab("📋 Scan Log"), font=("Consolas", 12), wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.tips_text = ctk.CTkTextbox(self.tabview.tab("💡 Mitigation Tips"), font=("Consolas", 12), wrap="word")
        self.tips_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.tips_text.insert("0.0", "💡 Tips appear after scan.\n")

        # History Tab
        self.history_frame = ctk.CTkScrollableFrame(self.tabview.tab("📜 Scan History"))
        self.history_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.history_title = ctk.CTkLabel(
        self.history_frame,
        text="🔍 Recent Scan History",
        font=("Consolas", 16, "bold"),
        text_color="#00ffff"
        )
        self.history_title.pack(pady=(0, 15))

        self.history_entries = []
        self.load_history_display()
 
        self.last_result = None
        self._scanning = False

    ICON_MAP = {
        "xss": "⚠️",
        "sql_injection": "🧨",
        "clickjacking": "👁️",
        "insecure_cookies": "🍪",
        "missing_headers": "🔒",
        "server_info": "📡",
        "cors": "🌐",
        "security_txt": "📄",
        "robots_txt": "🔍"
    }

    SEVERITY_COLORS = {
        "High": "#ff4d4d",
        "Medium": "#ffcc00",
        "Low": "#66ccff",
        "Info": "#aaaaaa"
    }

    def log(self, message):
        self.log_text.insert("end", message + "\n")
        # ✅ Auto-scroll to bottom
        self.log_text.see("end")
        self.root.update_idletasks()  # Ensure UI updates immediately

    def _animate_loading(self):
        if not self.loading:
            return
        dots = self.loading_dots[self.dot_index]
        self.scan_btn.configure(text=f"⏳ Scanning... {dots}")
        self.dot_index = (self.dot_index + 1) % len(self.loading_dots)
        self.root.after(150, self._animate_loading)  # Update every 150ms

    def _is_valid_domain(self, url):
    
        # Remove protocol if present
        clean = url.split("://")[-1].split("/")[0]
    # Basic domain regex
        return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', clean) is not None

    def start_scan(self):
        if self._scanning:
            return
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        if "://" in url:
           if not (url.startswith("http://") or url.startswith("https://")):
               messagebox.showerror("Invalid URL", "URL must start with http:// or https://")
               return
        else:
        # Auto-add https:// for cleaner input
              url = "https://" + url

        if not self._is_valid_domain(url):
               messagebox.showerror("Invalid Domain", "Please enter a valid domain (e.g., example.com)")
               return

        self._scanning = True
        self.loading = True
        self.scan_btn.configure(state="disabled")
        self.copy_btn.configure(state="disabled")
        self.progress.set(0)
        self.log(f"[+] Starting scan for: {url}")

        # Start animation
        self.dot_index = 0
        self._animate_loading()

        # Run scan in background to avoid freezing
        self.root.after(100, self._run_scan, url)

    def _run_scan(self, url):
        try:
            result = self.scanner.scan(url)
            self.last_result = result
            self.log("[✓] Scan completed!")
            self.display_scan_results(result)
            self.update_mitigation_tips(result)
        except Exception as e:
            self.log(f"[!] Scan failed: {e}")
        finally:
            self._scanning = False
            self.loading = False
            self.scan_btn.configure(state="normal", text="🚀 Start Scan")
            self.copy_btn.configure(state="normal")
            self.progress.set(1.0)
            self.load_history_display()

    def display_scan_results(self, result):
        self.log("\n--- DETAILED FINDINGS ---")
        checks = [
            "xss", "sql_injection", "clickjacking", "insecure_cookies",
            "missing_headers", "server_info", "cors", "security_txt", "robots_txt"
        ]

        for check in checks:
            if check not in result:
                continue
            value = result[check]
            icon = self.ICON_MAP.get(check, "⏺️")
            severity = self.scanner.get_severity(check)

            if value in ["Safe", "All secure", "Not disclosed", "N/A", "Found"]:
                self.log(f"✅ {icon} {check.replace('_', ' ').title()}: {value}")
            elif isinstance(value, list) and value:
                self.log(f"{icon} {check.replace('_', ' ').title()} → {severity} ⚠️")
                for item in value:
                    self.log(f"    • {item}")
            else:
                self.log(f"{icon} {check.replace('_', ' ').title()}: {value} → {severity} ⚠️")

    def update_mitigation_tips(self, result):
        self.tips_text.delete("0.0", "end")
        tips = self.scanner.get_mitigation_tips(result)
        if tips:
            for tip in tips:
                self.tips_text.insert("end", tip + "\n\n")
        else:
            self.tips_text.insert("end", "✅ No critical issues. Great job!\n")

    def copy_results(self):
        if not self.last_result:
            messagebox.showinfo("Copy", "No scan results to copy.")
            return

        report = "=== VULNASCAN SCAN REPORT ===\n"
        report += f"URL: {self.last_result['url']}\n"
        report += f"Time: {self.last_result['timestamp']}\n"
        report += "\nFINDINGS:\n"

        checks = [
            "xss", "sql_injection", "clickjacking", "insecure_cookies",
            "missing_headers", "server_info", "cors", "security_txt", "robots_txt"
        ]
        for check in checks:
            if check in self.last_result:
                val = self.last_result[check]
                if isinstance(val, list):
                    val = ", ".join(val)
                report += f"- {check.replace('_', ' ').title()}: {val}\n"

        self.root.clipboard_clear()
        self.root.clipboard_append(report)
        messagebox.showinfo("📋 Copied", "Full scan report copied to clipboard!")

    def export_to_csv(self):
        success = self.scanner.export_to_csv()
        if success:
            path = os.path.abspath("vulnscan/data/scan_history.csv")
            messagebox.showinfo("✅ Exported", f"Saved to:\n{path}")
        else:
            messagebox.showerror("❌ Failed", "No history to export.")

    def load_history_display(self):
        for widget in self.history_entries:
            widget.destroy()
        self.history_entries.clear()

        history_file = self.scanner.results_file
        if not os.path.exists(history_file):
            self._add_history_entry("📭 No scan history available.")
            return

        try:
            with open(history_file, "r") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    for entry in reversed(data[-5:]):
                        url = entry.get("url", "Unknown")
                        time = entry.get("timestamp", "Unknown time")[:19]
                        self._add_history_entry(f"🕒 {time} → {url}")
                else:
                    self._add_history_entry("📭 No scans recorded yet.")
        except Exception as e:
            self._add_history_entry(f"❌ Failed to load history: {e}")

    def _add_history_entry(self, text):
        label = ctk.CTkLabel(
            self.history_frame,
            text=text,
            font=("Consolas", 12),
            anchor="w",
            justify="left",
            wraplength=800,
            text_color="#ffffff",
            fg_color="transparent"
        )
        label.pack(anchor="w", pady=3, padx=5, fill="x")
        self.history_entries.append(label)