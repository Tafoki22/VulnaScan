# VulnaScan 🛡️

A lightweight **desktop vulnerability scanner** for educational use and **authorized security testing**.  
Built with **Python**, **customtkinter**, and **requests**, VulnaScan helps developers, students, and security enthusiasts identify common web misconfigurations — with a sleek, modern GUI.

> ⚠️ **ETHICAL USE ONLY**  
> **Never scan systems you don’t own or lack explicit written permission to test.**  
> Unauthorized use may violate the **Computer Fraud and Abuse Act (CFAA)** or other laws.

---

## 🖼️ GUI Preview

![VulnaScan GUI](screenshot.png)  
*Modern dark-themed interface with real-time logging, severity indicators, and mitigation tips.*

> 💡 *Replace `screenshot.png` with your actual screenshot (e.g., `ABC.png` or `2025.png`) and commit it to your repo!*

---

## 🔍 Features

- **Vulnerability Checks**:
  - 🔒 Missing security headers (`CSP`, `HSTS`, `X-Frame-Options`, `Permissions-Policy`, etc.)
  - 👁️ Clickjacking (missing `X-Frame-Options`)
  - ⚠️ Reflected XSS (basic payload test)
  - 🧨 SQL Injection (error-based detection)
  - 🍪 Insecure cookies (missing `Secure`, `HttpOnly` flags)
  - 📡 Server info disclosure
  - 🌐 Risky CORS (`Access-Control-Allow-Origin: *`)
  - 📄 Missing `security.txt` or exposed paths in `robots.txt`

- **User Experience**:
  - ✅ **Auto HTTPS fallback** (`https://` → `http://`)
  - 🎨 **Dark-themed modern GUI** with icons & severity levels (High/Medium/Low)
  - 📋 **Real-time scan log** with color-coded results
  - 💡 **Mitigation tips** based on findings
  - 🕒 **Scan history** saved to `vulnscan/data/results.json`
  - 📤 **Export to CSV** for reporting
  - 📋 **Copy full report** to clipboard
  - 🚀 **Progress bar** during scanning

---

## ⚠️ Ethical & Legal Notice

VulnaScan is intended **only** for:
- ✅ Learning web security concepts  
- ✅ Testing **your own websites or labs**  
- ✅ **Authorized** penetration testing  

**Do NOT use against any system without explicit permission.**  
Misuse may result in legal consequences.

---

## 🛠️ Requirements

- Python 3.7+
- `pip`

---

## 📦 Installation

```bash
git clone https://github.com/TAFOKI22/VulnaScan.git
cd VulnaScan
pip install -r requirements.txt