# 🔍 InfoGather Pro v3.0 — Cross-Platform OSINT Tool

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Python-3.x-green?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Use-Educational%20Only-yellow?style=for-the-badge"/>
</p>

A powerful, cross-platform **OSINT & Information Gathering Tool** built with Python.  
Automatically generates **HTML, TXT & JSON** reports after every scan.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🌐 **IP / GeoLocation** | Resolve domain to IP, country, city, ISP, timezone |
| 📋 **DNS Records** | A, MX, NS, TXT record enumeration |
| 📄 **WHOIS Lookup** | Registrar, creation/expiry dates, registrant info |
| 🔓 **Port Scanner** | 20+ common ports scanned with threading |
| 🌍 **Subdomain Finder** | 40+ subdomains checked concurrently |
| ⚙️ **Tech Detector** | CMS, frameworks, servers, CDN detection |
| 🔎 **OSINT** | Email, phone numbers, social media links from homepage |
| 👤 **Username Tracker** | Search username across 19+ platforms simultaneously |
| 📞 **Phone Lookup** | Country, carrier, number type, timezone from phone number |
| 📊 **Auto Reports** | HTML (dark theme) / TXT / JSON reports generated automatically |

---

## 👤 Username Tracker — Platforms Covered

> Enter a username and instantly check across **19+ platforms**:

GitHub • Twitter/X • Instagram • TikTok • Reddit • LinkedIn • Pinterest  
Tumblr • Medium • Dev.to • HackerOne • Bugcrowd • TryHackMe • HackTheBox  
YouTube • Telegram • GitLab • Pastebin • Keybase • Snapchat

---

## 📞 Phone Number Lookup

Provide any international phone number to get:
- 🌍 Country & Region
- 📡 Carrier / Network Provider
- 📱 Number Type (Mobile / Fixed Line / VoIP)
- 🕐 Timezone(s)
- 📋 International & National format

---

## 💻 Supported Platforms

| Platform | Status |
|----------|--------|
| 📱 Termux (Android) | ✅ Supported |
| 🐧 Kali Linux | ✅ Supported |
| 🟠 Ubuntu / Debian | ✅ Supported |
| 🦜 Parrot OS | ✅ Supported |
| 🪟 Windows | ✅ Supported |
| 📱 iSH (iOS) | ✅ Supported |

---

## 🚀 Installation & Usage

### Install Dependencies
```bash
pip install requests phonenumbers
```

### Clone Repository
```bash
git clone https://github.com/muhammed95rafi-arch/InfoGather-Pro-2.0.git
cd InfoGather-Pro-2.0
```

### Run — Interactive Menu (Recommended)
```bash
python3 infogather_v3.py
```

### Run — Full Domain Scan
```bash
python3 infogather_v3.py example.com
```

### Run — Username Tracker Only
```bash
python3 infogather_v3.py --username target_username
```

### Run — Phone Number Lookup Only
```bash
python3 infogather_v3.py --phone +971501234567
```

### Run — Specific Modules Only
```bash
python3 infogather_v3.py example.com --modules ip dns ports
```

### Windows
```cmd
pip install requests phonenumbers
python infogather_v3.py
```

---

## 🖥️ Interactive Menu

When run without arguments, an interactive menu appears:

```
╔══════════════════════════════════════════════════════════════╗
║          INFORMATION GATHERING TOOL PRO v3.0                 ║
╠══════════════════════════════════════════════════════════════╣
║  IP | DNS | WHOIS | Ports | Subdomains | Tech | OSINT        ║
║  Username Tracker | Phone Lookup | Auto Reports              ║
╚══════════════════════════════════════════════════════════════╝

  [1] Full Domain Scan
  [2] Username Tracker
  [3] Phone Number Lookup
  [4] Quick IP / GeoLocation
  [5] Port Scanner Only
  [6] Subdomain Finder Only
  [0] Exit
```

---

## 📊 Report Output

After every scan, **3 report formats** are auto-generated in the `reports/` folder:

- `infogather_<target>_<timestamp>.html` — Dark-themed visual report
- `infogather_<target>_<timestamp>.txt`  — Plain text report
- `infogather_<target>_<timestamp>.json` — JSON data export

---

## 🗂️ File Structure

```
InfoGather-Pro-2.0/
├── infogather_v2.py     # v2.0 — Original version
├── infogather_v3.0.py   # v3.0 — Latest (Username + Phone + Menu)
├── reports/             # Auto-generated reports (created on run)
└── README.md
```

---

## ⚠️ Disclaimer

> This tool is developed for **educational and authorized security testing purposes only**.  
> The developer is not responsible for any misuse or illegal activity.  
> Always obtain proper authorization before scanning any target.  
> **Only test systems you own or have explicit permission to test.**

---

## 📜 License

MIT License — Free to use, modify, and distribute with attribution.

---

## 👨‍💻 Developer

**Muhammed Khan**  
Cybersecurity Researcher | Penetration Tester  
[![GitHub](https://img.shields.io/badge/GitHub-muhammed95rafi--arch-black?style=flat&logo=github)](https://github.com/muhammed95rafi-arch)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muhammed%20Khan-blue?style=flat&logo=linkedin)](https://linkedin.com/in/muhammed-khan-a57498375)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-VISIONARY-red?style=flat)](https://tryhackme.com)
[![HackerOne](https://img.shields.io/badge/HackerOne-High%20Severity%20Finding-orange?style=flat)](https://hackerone.com)

---

<p align="center">⭐ Star this repo if you find it useful!</p>
