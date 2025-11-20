# VulnScan - Advanced Network Vulnerability Scanner

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

VulnScan is a powerful asynchronous network vulnerability scanner that combines port scanning, service detection, and vulnerability analysis using multiple security APIs.

## Features

- 🚀 **Asynchronous Port Scanning**: Fast and efficient scanning of multiple ports simultaneously
- 🔍 **Service Detection**: Detailed service fingerprinting using Nmap integration
- 🛡️ **Vulnerability Analysis**: Integration with multiple security APIs:
  - Vulners
  - Shodan
  - NVD (National Vulnerability Database)
- 📊 **Real-time Progress Tracking**: Visual progress bars and status updates
- 📝 **Comprehensive Reporting**: Detailed reports in both text and JSON formats
- 🎨 **Modern CLI Interface**: Color-coded output and interactive menus
- 🔐 **Secure API Key Management**: Encrypted storage of API credentials

## Prerequisites

- Python 3.8 or higher
- Nmap installed on your system
- API keys for enhanced functionality (optional):
  - Vulners API key
  - Shodan API key
  - Censys API key

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ch4tbl4nc/vulnscan.git
cd vulnscan
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install Nmap if not already present:
- Linux: `sudo apt-get install nmap`
- macOS: `brew install nmap`
- Windows: Download and install from [nmap.org](https://nmap.org/download.html)

## Usage

1. Start the scanner:
```bash
python vulnscan.py
```

2. Configure API keys (optional but recommended):
- The tool will prompt you to configure API keys on first run
- Keys are stored securely using encryption

3. Enter scan parameters:
- Target IP address
- Port range (optional, defaults to 1-65535)

4. View results:
- Real-time scan progress
- Color-coded vulnerability alerts
- Detailed service information
- Comprehensive vulnerability reports

## Configuration

API keys can be configured through the interactive menu or manually in the config file:

```yaml
# config/api_config.yaml
vulners_api_key: "your_encrypted_key"
shodan_api_key: "your_encrypted_key"
censys_api_key: "your_encrypted_key"
```

## Output Examples

The scanner provides various output formats:

1. Real-time CLI output with progress tracking:
```
[12:34:56] ✓ Port 80 is open
[12:34:57] ⚠ Port 80 (http) has 3 critical vulnerabilities!
```

2. Summary table of findings
3. Detailed text report: `scan_report_<ip>_<timestamp>.txt`
4. JSON export: `scan_results_<ip>_<timestamp>.json`

## Security Considerations

- Ensure you have permission to scan the target system
- Store API keys securely
- Use responsibly and in compliance with applicable laws and regulations
- Consider rate limiting when scanning multiple targets

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Nmap Project for port scanning capabilities
- Vulners, Shodan, and NVD for vulnerability data
- All contributors and security researchers

## Contact

- GitHub: [ch4tbl4nc](https://github.com/ch4tbl4nc)
- Discord: [ch4tbl4nc](https://discord.com/users/1421478562392834171)

## Disclaimer

This tool is intended for legal security auditing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or networks.
