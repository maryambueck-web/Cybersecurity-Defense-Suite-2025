# Cybersecurity-Defense-Suite-2025
Cybersecurity Defense Suite with Choco Intelligence :)
# 🛡️ Persistent Showdown - Cybersecurity Defense Suite

Advanced real-time protection against persistent malware attacks with specialized Choco attack intelligence.

## ⚡ Quick Start for End Users

**For immediate protection:**
1. Download `PersistentShowdown_AllInOne.ps1`
2. Run PowerShell as Administrator
3. Execute: `.\PersistentShowdown_AllInOne.ps1`
4. Select **Option 9 (AutoStart)** for automatic protection

This installs protection that starts automatically when your computer boots!

## 🎯 Features

### 🛡️ Real-Time Protection
- Active monitoring system that detects and blocks attacks as they happen
- Continuous protection against file creation, registry modifications, and malicious processes
- Choco intelligence for enhanced detection

### 🔍 Choco-Aware Defender
Comprehensive malware detection with timing-aware scanning for all 5 Choco attack vectors:
- **Registry Run Keys** (35-40s timing)
- **Startup VBS Scripts** (50-55s timing) 
- **Scheduled Tasks** (45s+60s delays)
- **IFEO Hijacking** (targeting common executables)
- **WMI Event Subscriptions** (70s triggers)

### 🎮 Additional Modes
- **Educational Attacker** - Safe malware simulator for testing
- **Persistent Watchdog** - Boot-time protection system
- **Competition Mode** - Automated attacker vs defender showdown
- **Testing Framework** - Comprehensive validation suite
- **Web Server** - HTTP deployment for isolated environments

## 🚀 Usage Examples

### Interactive Menu (Recommended)
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode Menu
```

### Automatic Protection (Best for end users)
```powershell
# Run as Administrator
.\PersistentShowdown_AllInOne.ps1 -Mode AutoStart
```

### Manual Real-Time Protection
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode RealTime
```

### Run Defender (Cleanup mode)
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode Defender -AutoRemediate
```

### Competition Demo
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode Competition
```

### Testing
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode Test
```

### Deploy HTTP Server
```powershell
.\PersistentShowdown_AllInOne.ps1 -Mode WebServer -ServerPort 8000
```

## 🎯 Choco Attack Intelligence

This defender includes specialized detection for the Choco attack framework:

### ⏱️ Timing-Aware Detection
- **30s**: IFEO hijacking attempts
- **35-40s**: Registry Run key installations (HKLM & HKCU)
- **45-60s**: Scheduled task deployments
- **50-55s**: Startup VBS script installations
- **70s**: WMI event subscription triggers

### 🎲 Pattern Recognition
- **SecurityHealthSystray_*** registry entries
- **MicrosoftEdgeAutoLaunch_*** registry entries
- **WindowsUpdateScan*** scheduled tasks
- **SystemMaintenance*** scheduled tasks
- **WindowsDefender.vbs** / **OfficeClickToRun.vbs** startup scripts
- **SystemEventMonitor_*** WMI consumers

### 🔐 Advanced Detection
- Base64 encoded PowerShell commands
- Hidden VBS script patterns
- Timing-based attack sequences
- Common executable hijacking (notepad.exe, cmd.exe, etc.)

## 📋 System Requirements

- **OS**: Windows 10/11
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights (for AutoStart mode)
- **Architecture**: x64 recommended

## 🔒 Security Features

- **Quarantine System** - Safe isolation of detected threats
- **Comprehensive Logging** - JSON-formatted reports
- **Watchdog Protection** - Prevents malware recreation
- **Real-time Monitoring** - Active threat blocking
- **Base64 Decoding** - Advanced payload analysis

## ⚠️ Security Notice

**Educational Use Only**: This suite is designed for cybersecurity education and testing in controlled environments. Always ensure you have proper authorization before testing security tools.

## 🏆 Competition Ready

Perfect for cybersecurity competitions and red team vs blue team exercises:
- Automated scoring system
- Real-time threat simulation
- Comprehensive reporting
- Professional presentation tools

## 📖 Operational Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Defender** | Remove malware and clean system | Post-infection cleanup |
| **Attacker** | Install educational malware | Testing and validation |
| **Watchdog** | Install persistent protection | Boot-time security |
| **Competition** | Automated demo | Presentations and competitions |
| **Test** | Comprehensive testing | Quality assurance |
| **Deploy** | Create deployment environment | Distribution setup |
| **WebServer** | HTTP server for remote deployment | Isolated environments |
| **RealTime** | Active real-time protection | Live monitoring |
| **AutoStart** | Install automatic startup protection | End-user deployment |
| **Menu** | Interactive mode selection | User-friendly interface |

## 🤝 Contributing

This project is designed for educational cybersecurity purposes. Feel free to:
- Report issues
- Suggest improvements
- Submit educational enhancements
- Share testing results

## 📄 License

Educational use only. Please ensure compliance with local laws and regulations.

---

*"The best defense is knowing your enemy's exact attack patterns."* 🛡️
