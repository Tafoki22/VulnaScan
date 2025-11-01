# VulnaScan 🛡️

A lightweight **desktop vulnerability scanner** for educational use and authorized security testing.  
Built with Python and Tkinter, VulnaScan helps developers, students, and security enthusiasts identify common web misconfigurations and vulnerabilities.

> ⚠️ **For authorized use only.** Never scan systems you don’t own or lack explicit permission to test.

---

## 🔍 Features

- **Passive & active checks**:
  - Missing security headers (`CSP`, `HSTS`, `X-Frame-Options`, etc.)
  - Clickjacking (missing `X-Frame-Options`)
  - Reflected XSS (basic payload test)
  - SQL Injection (error-based detection)
  - Insecure cookies (missing `Secure` flag)
  - Server version disclosure
- **Auto HTTPS fallback**: Tries `https://` first, falls back to `http://` if needed
- **User-friendly GUI** with real-time logging
- **Ethical disclaimer** on startup
- **Scan history** saved to `results.json`
- **Export results to CSV** for reporting

---

## ⚠️ Ethical & Legal Notice

VulnaScan is designed for:
- Learning cybersecurity concepts
- Testing your own websites or labs
- Authorized penetration testing

**Do not use this tool against systems you do not own or lack written permission to test.**  
Unauthorized scanning may violate laws such as the **Computer Fraud and Abuse Act (CFAA)** or local cybersecurity regulations.

---

## 🛠️ Requirements

- Python 3.7 or higher
- `requests` library

---

## 📦 Installation

```bash
git clone https://github.com/TAFOKI22/VulnaScan.git
cd VulnaScan
pip install -r requirements.txt