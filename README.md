# OSINT Intel

<p align=\"center\">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows\" alt=\"Windows\"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-green?style=for-the-badge\" alt=\"Version\"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge\" alt=\"License\"/>
</p>

<p align=\"center\">
  <b>Fast & Lightweight OSINT Threat Intelligence Dashboard</b><br>
  Analyze IPs, Domains, and File Hashes using multiple threat intelligence vendors
</p>

---

## Features

- **Multi-IP Analysis** - Analyze multiple IPs simultaneously (batch mode)
- **Private IP Detection** - Automatically identifies internal/private IP addresses
- **Domain Analysis** - DNS resolution + domain reputation check
- **Hash Lookup** - Support for MD5, SHA1, SHA256 file hashes
- **Interactive World Map** - Geolocation visualization with Leaflet
- **Multi-Vendor Support** - AbuseIPDB, VirusTotal, IPinfo integration
- **Threat Scoring** - Color-coded threat level indicators (Critical/High/Medium/Low/Clean)
- **Portable** - No installation required, runs as standalone .exe
- **Lightweight** - Minimal RAM footprint, fast startup

---

## Screenshot

<p align=\"center\">
  <img src="dashboard.png\" alt=\"OSINT Intel Dashboard\" width=\"800\"/>
</p>

---

## Download

📥 **[Download OSINT-Intel-2.0.0](https://github.com/francescoerrico2/Osint-Intel/releases/latest)**

---

## Usage

1. **Download** the portable or installer from [Releases](https://github.com/francescoerrico2/Osint-Intel/releases)
2. **Run** `OSINT-Intel-2.0.0-xxx.exe`
3. **Configure API Keys** (optional but recommended):
   - Click the ⚙️ Settings icon
   - Enter your API keys for enhanced threat intelligence
4. **Analyze**:
   - **IP Tab**: Enter one or more IP addresses (comma or newline separated)
   - **Domain Tab**: Enter a domain or URL
   - **Hash Tab**: Enter a file hash (MD5/SHA1/SHA256)

---

## API Keys (Free Tier Available)

For full threat intelligence data, configure these free API keys:

| Service | Description | Get Free Key |
|---------|-------------|--------------|
| **AbuseIPDB** | IP reputation & abuse reports | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| **VirusTotal** | Malware & threat analysis | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| **IPinfo** | Geolocation & ISP data | [ipinfo.io/account/token](https://ipinfo.io/account/token) |

> **Note**: The tool works without API keys but with limited data. IPinfo geolocation works without a key.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `F5` | Reload |
| `F12` | Developer Tools |
| `Ctrl+Shift+Delete` | Clear all data |
| `Alt+F4` | Exit |

---

## Threat Levels

| Level | Score | Color | Description |
|-------|-------|-------|-------------|
| 🔴 Critical | 80-100% | Red | High confidence malicious |
| 🟠 High | 60-79% | Orange | Likely malicious |
| 🟡 Medium | 40-59% | Yellow | Suspicious activity |
| 🔵 Low | 20-39% | Blue | Low risk |
| 🟢 Clean | 0-19% | Green | No threats detected |
| ⚫ Unknown | N/A | Gray | Insufficient data |

---

## Tech Stack

- **Frontend**: React, Tailwind CSS, Leaflet Maps
- **Backend**: Node.js (embedded)
- **Desktop**: Electron
- **APIs**: AbuseIPDB, VirusTotal, IPinfo

---

## Privacy

- All API keys are stored **locally** in your browser's localStorage
- No data is sent to third parties except the configured threat intelligence APIs
- No telemetry or tracking

---

## License

MIT License - See [LICENSE](LICENSE) for details

---

"
