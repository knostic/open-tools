# 🔒 Vulnerable Packages Scanner

A comprehensive, standalone bash script to detect and purge vulnerable npm packages across your entire system or specific directories.

## 🚀 Quick Start

### **Prerequisites**
Before running the script, you need to provide execution permissions:

```bash
chmod +x main_script.sh
```

### **Basic Usage**
```bash
# Check current directory for vulnerabilities
./main_script.sh

# Check entire system
./main_script.sh --system-wide

# Check specific directory
./main_script.sh --path /path/to/your/project

# Safe preview of what would be purged
./main_script.sh --purge --dry-run
```

## 🎯 Overview

This tool scans for known vulnerable packages from supply chain attacks and provides options to safely remove them. It's designed to be:

- **Standalone** - No external dependencies or config files required
- **Safe** - Defaults to scan-only mode, requires explicit flags for destructive operations
- **Comprehensive** - Scans all package managers (npm, yarn, pnpm, bun) and multiple languages
- **Fast** - Optimized for performance with parallel processing and smart caching

## 📋 Features

### **🔍 Comprehensive Scanning**
- **Package Managers**: npm, yarn, pnpm, bun
- **Lock Files**: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb
- **Languages**: Node.js, Python, Ruby, Go, Rust
- **Locations**: Git repositories, system caches, global installs, virtual environments

### **🛡️ Security Features**
- **Safe Defaults** - Scan-only mode by default
- **Dry-Run Mode** - Preview changes without making them
- **Confirmation Prompts** - Prevents accidental deletions
- **Path Validation** - Prevents directory traversal attacks
- **Permission Checks** - Validates access before operations

## 🎛️ Usage

### **Basic Commands**
```bash
# Scan current directory (default)
./main_script.sh

# Scan entire system
./main_script.sh --system-wide

# Scan specific directory
./main_script.sh --path /path/to/dir

# Scan multiple directories
./main_script.sh --paths /path1,/path2,/path3

# Scan directory without subdirectories
./main_script.sh --path /path --no-subdirs
```

### **Purge Operations**
```bash
# Safe preview (recommended first)
./main_script.sh --purge --dry-run

# Purge with confirmation
./main_script.sh --purge

# Purge without confirmation
./main_script.sh --purge --yes

# Purge and reinstall dependencies
./main_script.sh --purge --reinstall
```

### **Output Options**
```bash
# Verbose output with progress
./main_script.sh --verbose

# Skip JSON report generation
./main_script.sh --no-json

# Generate JSON report (default)
./main_script.sh --json
```

## 🔧 Configuration

### **Environment Variables**
```bash
# Search path (default: current directory)
SEARCH_PATH=/path/to/repos ./main_script.sh

# Maximum search depth (default: 10)
MAX_DEPTH=5 ./main_script.sh

# Maximum parallel jobs (default: 4)
MAX_JOBS=8 ./main_script.sh

# Report file name
REPORT_FILE=my-report.json ./main_script.sh
```

### **Mode Switching**
The script includes both TEST and PRODUCTION modes:

**TEST Mode (Default - Safe)**
- Uses safe test packages (lodash:4.17.21)
- Perfect for testing and demonstrations
- No risk of false positives

**PRODUCTION Mode**
- Uses real vulnerable packages from supply chain attacks
- 27 known vulnerable packages
- For actual security scanning

To switch modes, edit line 78 in the script:
```bash
# For TESTING (default):
SCAN_MODE="TEST"

# For PRODUCTION:
SCAN_MODE="PRODUCTION"
```

## 🚨 Vulnerable Packages

### **Current Production Packages (27 packages)**

**Supply Chain Attack Packages:**
- ansi-styles:6.2.2, debug:4.4.2, chalk:5.6.1
- strip-ansi:7.1.1, supports-color:10.2.1, ansi-regex:6.2.1
- wrap-ansi:9.0.1, slice-ansi:7.1.1, is-arrayish:0.3.3
- color-convert:3.1.1, color-name:2.0.1, color-string:2.1.1
- simple-swizzle:0.2.3, error-ex:1.3.3, has-ansi:6.0.1
- supports-hyperlinks:4.1.1, chalk-template:1.1.1, backslash:0.2.1
- color:5.0.1

**Additional Vulnerable Packages:**
- @duckdb/node-api:1.3.3, @duckdb/node-bindings:1.3.3
- duckdb:1.3.3, @duckdb/duckdb-wasm:1.29.2
- prebid.js:10.9.2, prebid-universal-creative:latest
- prebid:latest, proto-tinker-wc:0.1.87

## 🔒 Security Considerations

### **Safe Usage**
1. **Always start with dry-run**: `./main_script.sh --purge --dry-run`
2. **Use TEST mode for testing**: Set `SCAN_MODE="TEST"`
3. **Backup important data** before purging
4. **Review results** before confirming purge operations

### **Permissions**
- **Read access** required for scanning
- **Write access** required for purging
- **Admin/sudo** may be needed for system-wide scans

## 🛠️ Troubleshooting

### **Common Issues**

**Permission Denied**
```bash
# Run with appropriate permissions
sudo ./main_script.sh --system-wide
```

**Script Hangs**
```bash
# Use verbose mode to see progress
./main_script.sh --verbose

# Reduce search depth
MAX_DEPTH=3 ./main_script.sh
```

### **Exit Codes**
- **0** - Success, no vulnerabilities found
- **1** - Vulnerabilities found
- **2** - Script errors
- **3** - Permission denied

## 🔄 CI/CD Integration

### **GitHub Actions**
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Scan
        run: |
          chmod +x main_script.sh
          ./main_script.sh --verbose
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### **Getting Help**
- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check this README and inline help
- **Community**: Join discussions in GitHub Discussions

### **Reporting Vulnerabilities**
If you discover a new vulnerable package, please:
1. Verify it's a real security issue
2. Test with the script in TEST mode first
3. Submit a pull request with the package details
4. Include CVE or security advisory links if available

---

**⚠️ Important**: This tool is designed for security professionals and developers. Always test in a safe environment before using in production. The authors are not responsible for any data loss or system damage.
