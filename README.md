# 🛠️ Open Tools

A collection of useful standalone tools that solve real problems for developers and security professionals.

## 🎯 About This Repository

This repository contains standalone tools designed to solve common problems developers and security professionals face. Each tool is:

- **Standalone** - No complex dependencies or setup required
- **Well-documented** - Clear instructions and examples
- **Community-tested** - Used and validated by the community
- **Open source** - Free to use, modify, and distribute

## 📦 Available Tools

### 🔒 [Vulnerable Packages Scanner](./vulnerable_packages_scanner/)

A comprehensive bash script to detect and purge vulnerable npm packages across your entire system or specific directories.

**Features:**
- Scans for 27 known vulnerable packages from supply chain attacks
- Supports multiple package managers (npm, yarn, pnpm, bun)
- Safe defaults with dry-run mode
- JSON reporting and CI/CD integration
- All packages verified as supply chain attack vectors

**Quick Start:**
```bash
cd vulnerable_packages_scanner
chmod +x main_script.sh
./main_script.sh --help
```

### 🛡️ [GlassWorm YARA Detection Suite](./glassworm_yara/)

A comprehensive YARA rule set for detecting GlassWorm malware patterns, including blockchain C2, credential harvesting, and stealth techniques.

**Features:**
- **Blockchain C2 Detection** - Detects Solana blockchain-based command and control infrastructure
- **Credential Harvesting** - Identifies NPM, GitHub, OpenVSX, Git, and SSH credential theft patterns
- **RAT Capabilities** - Detects Remote Access Trojan patterns including SOCKS proxy and VNC
- **Self-Propagation** - Identifies automated package publishing and worm spread mechanisms
- **Crypto Wallet Targeting** - Detects targeting of 49+ cryptocurrency wallet extensions
- **Unicode Stealth** - Identifies invisible Unicode variation selectors used to hide malicious code
- **Google Calendar C2** - Detects Google Calendar API usage for command and control fallback

**Quick Start:**
```bash
# Use with YARA scanner
yara glassworm_yara/blockchain_c2.yar suspicious_file.js
yara glassworm_yara/credential_harvesting.yar /path/to/scan/
yara glassworm_yara/rat_capabilities.yar malicious_package/

# Scan all rules at once
yara glassworm_yara/*.yar target_directory/
```

*More tools coming soon! This repository is actively growing with new utilities.*

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### **Adding New Tools**
1. Fork the repository
2. Create a new directory for your tool
3. Include a comprehensive README with:
   - Clear description of what the tool does
   - Installation instructions
   - Usage examples
   - Prerequisites and requirements
4. Ensure your tool is standalone and well-documented
5. Submit a pull request

### **Improving Existing Tools**
1. Fork the repository
2. Make your improvements
3. Update documentation as needed
4. Test thoroughly
5. Submit a pull request

### **Guidelines**
- **Standalone**: Tools should work without complex setup
- **Documentation**: Clear, comprehensive README files
- **Testing**: Include test cases where applicable
- **Security**: Follow security best practices
- **License**: Use MIT or compatible open source license

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## 🆘 Support

### **Getting Help**
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join community discussions in GitHub Discussions
- **Documentation**: Check individual tool README files

### **Community Guidelines**
- Be respectful and constructive
- Help others learn and grow
- Share knowledge and best practices
- Follow the code of conduct

## 🌟 Star History

If you find these tools useful, please consider giving us a star! It helps others discover the repository and encourages continued development.

## 🔄 Roadmap

We're actively working on expanding this collection with tools that solve real problems. Some areas we're exploring:

- **Security Tools** - Additional vulnerability scanners, security analyzers
- **Development Utilities** - Code quality tools, automation scripts
- **DevOps Tools** - Deployment helpers, monitoring utilities
- **Data Processing** - ETL scripts, data validation tools
- **System Administration** - System monitoring, maintenance scripts

*Have a tool idea? We'd love to hear from you!*

## 📊 Statistics

- **Tools Available**: 2 (actively growing!)
- **Languages**: Bash, YARA (with plans for Python, JavaScript, and more)
- **License**: MIT
- **Community**: Open source contributors welcome

---

**Made with ❤️ by the community, for the community**

*This repository is maintained by volunteers who believe in the power of open source tools to make development and security work more efficient and accessible to everyone.*
