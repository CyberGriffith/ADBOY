# 🔥 ADBOY — Active Directory Attack Path Analyzer

### By Anuk Duljaya 🇱🇰

ADBOY is a professional Active Directory enumeration and attack-path analysis tool designed to identify privilege escalation paths in AD environments.

---

## 🚀 Features

* 🔍 LDAP vulnerability scanning
* 🧠 BloodHound JSON parsing
* ⚠️ Detection of dangerous ACL edges
* 🔗 Privilege path identification
* 🎨 Colorized professional output
* 📊 Top risk summary
* 📁 JSON export for reporting

---

## 🧪 Supported Attack Detection

* Kerberoasting
* AS-REP Roasting
* ACL Abuse (GenericAll, WriteDACL, etc.)
* Shadow Credentials (AddKeyCredentialLink)
* Delegation Abuse
* Privileged Group Paths

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/ADBOY.git
cd ADBOY
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🧠 Usage

### LDAP Scan

```bash
python3 adboy.py ldap -d domain.local -u user -p pass -s <dc-ip>
```

---

### BloodHound Analysis

```bash
python3 adboy.py bh --bh-dir ./bloodhound --start 'USER@DOMAIN.LOCAL'
```

---

## 🧾 Example Output

```
CRITICAL: PENTEST -> GenericAll -> ENTERPRISE ADMINS
→ Full domain compromise path detected
```

---

## ⚠️ Disclaimer

This tool is intended for:

* Educational purposes
* Authorized penetration testing
* CTF environments (Hack The Box, TryHackMe)

---

## 👨‍💻 Author

**Anuk Duljaya**
Cybersecurity Student | AD Exploitation Enthusiast
