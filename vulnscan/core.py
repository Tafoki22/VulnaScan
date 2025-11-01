# vulnscan/core.py
import requests
import json
import os
import csv
from datetime import datetime

class VulnaScanner:
    def __init__(self, data_dir="vulnscan/data"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.results_file = os.path.join(self.data_dir, "results.json")
        self.scan_history = self._load_history()

    def _load_history(self):
        if not os.path.exists(self.results_file):
            return []
        try:
            with open(self.results_file, "r") as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Warning: Failed to load history ({e}). Starting fresh.")
            return []

    def _save_history(self):
        with open(self.results_file, "w") as f:
            json.dump(self.scan_history, f, indent=2, default=str)

    def _format_error(self, e):
        msg = str(e).lower()
        if "connection" in msg and ("reset" in msg or "abort" in msg):
            return "Blocked by server (common for security tests)"
        elif "timeout" in msg:
            return "Server did not respond in time"
        elif "name or service not known" in msg or "getaddrinfo failed" in msg:
            return "Domain not found"
        else:
            return "Scan interrupted"

    def scan(self, url):
        original_input = url
        # Auto-scheme detection
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            try:
                requests.get(url, timeout=5)
            except Exception:
                url = "http://" + original_input

        result = {
            "url": url,
            "timestamp": str(datetime.now()),
            "https_used": url.startswith("https://"),
            "xss": "N/A",
            "clickjacking": "N/A",
            "sql_injection": "N/A",
            "insecure_cookies": "N/A",
            "missing_headers": "N/A",
            "server_info": "N/A"
        }

        result["xss"] = self._check_xss(url)
        result["clickjacking"] = self._check_clickjacking(url)
        result["sql_injection"] = self._check_sql_injection(url)
        result["insecure_cookies"] = self._check_cookie_security(url)
        result["missing_headers"] = self._check_security_headers(url)
        result["server_info"] = self._check_server_info(url)

        self.scan_history.append(result)
        self._save_history()
        return result

    def _check_xss(self, url):
        try:
            payload = "<script>alert('XSS')</script>"
            res = requests.get(url, params={'q': payload}, timeout=10)
            return "Vulnerable" if payload in res.text else "Safe"
        except Exception as e:
            return self._format_error(e)

    def _check_clickjacking(self, url):
        try:
            res = requests.get(url, timeout=10)
            if "X-Frame-Options" not in res.headers:
                return "Vulnerable"
            return "Safe"
        except Exception as e:
            return self._format_error(e)

    def _check_sql_injection(self, url):
        try:
            payload = "' OR '1'='1"
            res = requests.get(url, params={'id': payload}, timeout=10)
            text = res.text.lower()
            if "sql" in text or "syntax" in text or "error" in text:
                return "Vulnerable"
            return "Safe"
        except Exception as e:
            return self._format_error(e)

    def _check_cookie_security(self, url):
        try:
            res = requests.get(url, timeout=10)
            insecure = []
            for cookie in res.cookies:
                if not cookie.secure:
                    insecure.append(cookie.name)
            return insecure if insecure else "All secure"
        except Exception as e:
            return self._format_error(e)

    def _check_security_headers(self, url):
        try:
            res = requests.get(url, timeout=10)
            headers = res.headers
            missing = []

            required = {
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Strict-Transport-Security"
            }

            for header in required:
                if header not in headers:
                    missing.append(header)

            return missing if missing else "All present"
        except Exception as e:
            return self._format_error(e)

    def _check_server_info(self, url):
        try:
            res = requests.get(url, timeout=10)
            server = res.headers.get("Server", "").strip()
            if server:
                if any(c.isdigit() for c in server):
                    return f"Version disclosed: {server}"
                else:
                    return f"Server identified: {server}"
            return "Not disclosed"
        except Exception as e:
            return self._format_error(e)

    def export_to_csv(self, csv_path="vulnscan/data/scan_history.csv"):
        if not self.scan_history:
            return False

        def flatten(value):
            if isinstance(value, list):
                return "; ".join(str(v) for v in value)
            return str(value)

        fieldnames = set()
        for entry in self.scan_history:
            fieldnames.update(entry.keys())
        fieldnames = sorted(fieldnames)

        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in self.scan_history:
                    flat_entry = {k: flatten(v) for k, v in entry.items()}
                    for key in fieldnames:
                        flat_entry.setdefault(key, "")
                    writer.writerow(flat_entry)
            return True
        except Exception as e:
            print(f"[!] CSV export failed: {e}")
            return False