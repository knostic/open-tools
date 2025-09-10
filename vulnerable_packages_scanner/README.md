# 🔒 Vulnerable Packages Scanner

A simple standalone bash script we developed for our own use at [knostic.ai](https://www.knostic.ai/), to detect and purge vulnerable npm packages across the entire system, or specific directories. This tool addresses the [debug package vulnerability as described by Snyk.](https://security.snyk.io/vuln/SNYK-JS-DEBUG-12552895) 

## 🚀 Quick Start

### **Prerequisites**
Before running the script, you need to provide execution permissions:

```bash
chmod +x main_script.sh
```

### **Basic Usage**
```bash
# Check current directory for vulnerabilities (default - safe, non-destructive)
./main_script.sh

# Check entire system
./main_script.sh --system-wide

# Check specific directory
./main_script.sh --path /path/to/your/project

# Safe preview of what would be purged
./main_script.sh --purge --dry-run
```

**Default Behavior**: Running `./main_script.sh` with no flags performs a **safe, non-destructive scan** of the current directory only. No packages are purged or modified - it only reports vulnerabilities found.

**Testing**: To test the scanner safely, install lodash (`npm install lodash@4.17.21`) and use TEST mode to verify scan and purge functionality works correctly.

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
# Scan current directory (default - safe, non-destructive scan only)
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

**Note**: All scan commands above are **safe and non-destructive** by default. They only report vulnerabilities found without making any changes to your system.

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

**PRODUCTION Mode (Default)**
- Uses real vulnerable packages from supply chain attacks
- 27 known vulnerable packages
- For actual security scanning in production environments

**TEST Mode (Safe for Testing)**
- Uses safe test packages (lodash:4.17.21) - a legitimate, non-malicious package
- Perfect for testing the scanner functionality and purge operations in a controlled environment
- Allows you to verify that the scan and purge mechanisms work correctly without risk
- No risk of false positives or accidental removal of real packages

To switch modes, edit line 93 in the script:
```bash
# For PRODUCTION (default):
SCAN_MODE="PRODUCTION"

# For TESTING:
SCAN_MODE="TEST"
```

## 🧪 Testing with White Package

### **Installing the Test Package (lodash)**

To test the scanner functionality safely, you can install the white package (lodash) that's used in TEST mode:

#### **Option 1: Install in a Test Directory**
```bash
# Create a test directory
mkdir test-scanner
cd test-scanner

# Initialize npm project
npm init -y

# Install the white package (lodash:4.17.21)
npm install lodash@4.17.21

# Test the scanner
../main_script.sh
```

#### **Option 2: Install in Existing Project**
```bash
# In your existing project directory
npm install lodash@4.17.21

# Switch to TEST mode first (edit line 93 in main_script.sh)
# Change: SCAN_MODE="PRODUCTION" to SCAN_MODE="TEST"

# Test the scanner
./main_script.sh
```

#### **Option 3: Test Purge Functionality**
```bash
# Install the test package
npm install lodash@4.17.21

# Test dry-run purge (safe preview)
./main_script.sh --purge --dry-run

# Test actual purge (removes lodash)
./main_script.sh --purge --yes
```

### **Why Use lodash for Testing?**
- **✅ Safe**: lodash is a legitimate, widely-used utility library
- **✅ Non-malicious**: No security risks or malicious code
- **✅ Controlled**: You can install/uninstall it safely
- **✅ Realistic**: Tests the actual scan and purge mechanisms
- **✅ Reversible**: Easy to reinstall if needed

### **Testing Workflow**
1. **Switch to TEST mode**: Edit line 93 in `main_script.sh` to set `SCAN_MODE="TEST"`
2. **Install lodash**: `npm install lodash@4.17.21`
3. **Verify scan**: `./main_script.sh` (should detect lodash)
4. **Test dry-run**: `./main_script.sh --purge --dry-run` (preview removal)
5. **Test purge**: `./main_script.sh --purge --yes` (actual removal)
6. **Reinstall if needed**: `npm install lodash@4.17.21`
7. **Switch back to PRODUCTION**: Change `SCAN_MODE="TEST"` back to `SCAN_MODE="PRODUCTION"`

## 🚨 Vulnerable Packages

### **Current Production Packages (27 packages)**

**All packages are from known supply chain attacks:**

- ansi-styles:6.2.2
- debug:4.4.2
- chalk:5.6.1
- strip-ansi:7.1.1
- supports-color:10.2.1
- ansi-regex:6.2.1
- wrap-ansi:9.0.1
- slice-ansi:7.1.1
- is-arrayish:0.3.3
- color-convert:3.1.1
- color-name:2.0.1
- color-string:2.1.1
- simple-swizzle:0.2.3
- error-ex:1.3.3
- has-ansi:6.0.1
- supports-hyperlinks:4.1.1
- chalk-template:1.1.1
- backslash:0.2.1
- color:5.0.1
- @duckdb/node-api:1.3.3
- @duckdb/node-bindings:1.3.3
- duckdb:1.3.3
- @duckdb/duckdb-wasm:1.29.2
- prebid.js:10.9.2
- prebid-universal-creative:latest
- prebid:latest
- proto-tinker-wc:0.1.87

## 🔒 Security Considerations

### **Safe Usage**
1. **Default is safe**: `./main_script.sh` (no flags) only scans and reports - no changes made
2. **Always start with dry-run**: `./main_script.sh --purge --dry-run`
3. **Use TEST mode for testing**: Set `SCAN_MODE="TEST"` to test with safe packages (lodash)
4. **Test in controlled environment**: Install lodash to verify scan/purge functionality works
5. **Backup important data** before purging in production
6. **Review results** before confirming purge operations

**Note**: The script defaults to PRODUCTION mode, which scans for real vulnerable packages. For testing, switch to TEST mode to use safe packages.

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
