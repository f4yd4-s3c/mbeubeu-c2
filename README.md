# 🛠️ MBEUBEU C2 Framework  
![MBEUBEU Logo](https://f4yd4-s3c.github.io/screenshots/mbeubeu.png)



**MBEUBEU** is a flexible and stealthy open-source Command and Control (C2) framework designed for modern red team operations and adversary simulation. It supports multiple agent types, including Windows and Linux, and integrates advanced features for post-exploitation, evasion, and operator collaboration.

**MBEUBEU** is fully written in Go (Golang), making it cross-platform. The project is open to contributions from anyone who wants to help make it more powerful and adaptable.
While **MBEUBEU** is not yet feature-complete and doesn't aim to compete directly with other C2 frameworks, it is continuously evolving over time with community input and real-world red teaming needs in mind.


> ⚠️ **DISCLAIMER:** This tool is intended for **educational** purposes and **authorized** penetration testing only. Any misuse is strictly prohibited and not the responsibility of the developer.

---

## 🌐 Documentation

📝 **Official Docs:** [https://f4yd4-s3c.github.io/](https://f4yd4-s3c.github.io/)

![MBEUBEU Logo](https://f4yd4-s3c.github.io/screenshots/start-ts.gif)
---

## ✨ Features

- 🚀 **Cross-Platform Agents** (Windows, Linux)
- 🌐 **HTTP/HTTPS/QUIC Listeners**
- 🧱 **Modular YAML C2 Profiles**
- 🛡️ **AV/EDR Evasion** with Sandbox Detection
- 🛡️ **Defence Analysis**
- ⏳ **Smart Sleep and Jitter Delays**
- 💻 **Command Execution** (Shell, PowerShell)
- 🖼️ **Stealth Screenshot Capture** (Window-based)
- 📁 **File Transfer System** (Upload/Download)
- 🔒 **Credential Dumping** with Mimikatz & SharpKatz
- 📦 **In-Memory Execution:**
  - `execute-assembly` (.NET)
  - BOF (Beacon Object File)
- 🧠 **Integrated Modules:**
  - Mimikatz
  - PowerView
- 📎 **USB Propagation** (Monitor and infect plugged devices)
- 🧾 **Office Macro Embedding**
- 🌉 **Lateral Movement:**
  - WinRM
  - PSExec
  - Pass-the-Hash (PTH)
  - DCSync
- 💻 **Persistence:**
  - persist_startup
  - persist_registryrun
  - persist_schtask
  - persist_winlogon
- 🧾 **Reporting:**
  - report_start
  - report_stop
- 🧅 **SOCKS5 Tunneling Proxy**
- 🔔 **Blue Team Detection & Redirection**

---

## ⚙️ Getting Started

**Requirements**
  - Go version ≥ 1.23.0

**Tested on**
  - Ubuntu 25.04 / 24.04
  - Kali Linux
  - WSL (Windows Subsystem for Linux)
  - Parrot OS

## 🧪 Installation Steps
1. **Clone the repo**
   ```bash
   git clone https://github.com/f4yd4-s3c/mbeubeu-c2.git
   cd mbeubeu-c2
   bash install.sh  

📝 **Official Docs:** [https://f4yd4-s3c.github.io/](https://f4yd4-s3c.github.io/)
---
## 🙏 Acknowledgements
Special thanks to the mentors and educational platforms that inspired this project:

🎓 **Rasta Mouse Course**
For the [C2 Development in C#](https://training.zeropointsecurity.co.uk/courses/c2-development-in-csharp)  which provided deep insight into operational security and modular architecture.

🧠 **Maldev Academy**
[For advanced malware development](https://maldevacademy.com/) and in-memory evasion techniques.

---

## 🤝 Contributions
Got an idea? Found a bug? Want to add a feature?
Contributions, issues, and pull requests are welcome! Feel free to fork, modify, and suggest improvements.


## 💙 Donate  
[buymeacoffee](https://www.buymeacoffee.com/f4yd4)  

[paypal](https://paypal.me/f4yd4s3c)

## 🇵🇸 Solidarity 
 -  I stand with the people of Gaza.  
 -  Please don’t forget to help Gaza victims. 🕊️ [Donate via UNICEF Gaza Victims  ](https://www.unicef.org/emergencies/children-gaza-need-lifesaving-support)


## follow me on :
[linkedin](https://linkedin.com/in/p4p4m4n3)  

[twitter](https://twitter.com/in/p4p4m4n3)  

**For sponsorship or service inquiries, please contact mane.papa@outlook.com.**

📜 License
Distributed under the MIT License. See LICENSE for details.



