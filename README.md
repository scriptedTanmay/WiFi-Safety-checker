# 🌐 Public WiFi Safety Checker

A Python-based GUI tool to analyze public WiFi networks and check their security.  
It scans for encryption type, captive portals, DNS hijacking, speed, and generates a risk score with safety suggestions.  
Useful for students, travelers, and cybersecurity learners.  

---

## ✨ Features
- 🔒 Detects WiFi encryption type (Open, WEP, WPA, WPA2, WPA3).  
- 🌍 Captive portal detection (checks if network redirects to login pages).  
- 🧭 DNS hijacking test (ensures DNS requests aren’t tampered with).  
- ⚡ Speed & latency test (using `speedtest-cli`).  
- 📊 Auto safety risk score (0–100).  
- 📂 Export report to JSON file for later review.  
- 🖥️ Simple cross-platform GUI (Tkinter).  
- 🌙 Dark Mode UI planned for next updates.  

---

## 🛠️ Installation
Clone the repository:
```bash
git clone https://github.com/your-username/public-wifi-safety-checker.git
cd public-wifi-safety-checker
