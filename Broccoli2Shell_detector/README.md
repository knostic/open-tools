# 🥦 Broccoli2Shell Detector

A standalone, read-only bash script we developed at [knostic.ai](https://www.knostic.ai/) to find code exposed to **Broccoli2Shell (CVE-2026-111497)** in a git repository and on the machine it runs on. Every finding comes with a suggested fix.

Broccoli2Shell is an out-of-bounds write in Google's reference Brotli C decoder (versions **1.0.3 through 1.2.0**). A crafted Brotli stream can turn it into a crash, a memory leak or remote code execution. You are exposed if your code, or any library it uses, decompresses Brotli data that someone else controls. That includes HTTP clients that decode `Content-Encoding: br` responses on their own: Node's `fetch()`, and Python's requests/urllib3, aiohttp and httpx whenever a Brotli package is installed.

The upstream fix is google/brotli commit `0ed4268`, released as Brotli **1.0.10 / 1.1.1 / 1.2.1**. Full write-up: [broccoli2shell.com](https://broccoli2shell.com).

## 🚀 Quick Start

### **Prerequisites**
- bash 3.2+ (the macOS default works), plus standard `find`, `grep`, `sed` and `awk`
- macOS or Linux
- Optional: `node`, `python3`, `brew`, `dpkg`/`rpm`/`apk`, `php`, `gem` (each is checked only if present)

```bash
chmod +x broccoli2shell-detect.sh
```

### **Basic Usage**
```bash
# Scan the git repository in the current directory, plus this machine
./broccoli2shell-detect.sh

# Scan a specific repository
./broccoli2shell-detect.sh /path/to/repo

# Repository only, e.g. in CI
./broccoli2shell-detect.sh --no-system

# Show all options and how detection works
./broccoli2shell-detect.sh --help
```

**Default behaviour**: the script only reads files. It installs nothing, changes nothing and never runs project code. Python interpreters are started with `-I` only to read installed package metadata.

## 🎛️ Options

| Option | Description |
|---|---|
| `--no-system` | Scan the repository only; skip the runtimes, virtualenvs and libraries installed on this machine |
| `--no-binaries` | Skip scanning native binaries for an embedded decoder (faster) |
| `--strict` | Also exit with 1 when only warnings were found |
| `--no-color` | Plain output (also honours `NO_COLOR`) |
| `-h`, `--help` | Show help, including how each check works |

### **Exit Codes**
- **0** - No vulnerable component found
- **1** - Vulnerable component found (or any warning with `--strict`)
- **2** - Usage error

## 📋 What It Checks

### **🟩 Node.js**
Node.js bundles its own copy of Brotli, so only the Node.js version matters. Versions below **22.23.4**, **24.22.1** and **26.12.1** are vulnerable, and so is every end-of-life line (≤ 21, 23, 25), which will not get a fix.
- **Version pins in the repo**: `.nvmrc`, `.node-version`, `.tool-versions`, `package.json` (volta/engines), Dockerfile `FROM node:<tag>` (build `ARG` defaults are resolved), `image: node:<tag>` in compose/k8s/GitLab/CircleCI YAML, and GitHub Actions `node-version` matrices (reported as warnings)
- **Floating tags** such as `node:24`, `node:alpine` and `lts/*`, which are only safe if they resolved to a patched release when the image was built
- **Lockfiles and `node_modules`** (npm, yarn, pnpm, bun): `iltorb`, which bundles an old decoder; Express 5.0–5.3 and body-parser 2.0–2.3 are reported as exposure paths because they decode `br` request bodies
- **This machine**: the `node` on `PATH`, plus every install under nvm, fnm, volta, asdf, mise, n and Homebrew

### **🐍 Python**
The PyPI packages **Brotli < 1.2.1** and **brotlicffi < 1.2.1.0** compile the vulnerable decoder. Your code doesn't need to import them to be exposed.
- **Manifests and lockfiles**: `requirements*.txt` / `.in`, `pyproject.toml`, `setup.cfg` / `setup.py`, `Pipfile` / `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` and conda environment files. Exact pins are checked, and so are constraints that still allow a vulnerable release (`>=1.0`) or force one (`<1.2.1`, `~=1.1.0`)
- **Extras** that pull Brotli in (`httpx[brotli]`, `aiohttp[speedups]`), plus pyarrow and duckdb, which bundle unpatched copies
- **Installed packages** in virtualenvs inside the repo, in every interpreter on `PATH`, pyenv and conda, and in virtualenvs kept elsewhere by **Poetry, pipx, uv tools, pipenv and virtualenvwrapper**
- **Compiled libraries bundled in packages**, such as the `libbrotlidec` inside Pillow wheels, found by the binary check below

### **🐧 System Library**
- `libbrotlidec` / `libbrotli1` from apt/dpkg (also checks whether the package changelog mentions the CVE), rpm, apk, Homebrew and MacPorts
- On Linux, processes that still use an old, replaced `libbrotlidec` are listed so you can restart them

### **🔬 Native Binaries and Vendored Sources**
- **Binary check**: every Brotli decoder contains the string `_ERROR_FORMAT_EXUBERANT_NIBBLE`, and only patched ones also contain `_ERROR_FORMAT_BLOCK_SWITCH` (the fix adds error code −17). The script checks `.node`, `.so`, `.dylib`, `.pyd`, `.dll` and `.a` files in the repo, Python packages and system libraries for both strings. That catches vendored and statically linked copies whatever version they claim to be.
- **Vendored C sources**: a vendored `decode.h` is patched if it defines the `BLOCK_SWITCH` error code. References to `google/brotli` in CMake, meson, conan, vcpkg, bazel and `.gitmodules` are version-checked.

### **🧩 Other Ecosystems**
Ruby brotli gem < 0.9.1, PHP brotli extension < 0.21.1, Go `andybalholm/brotli` (crash only) and `cbrotli`, Rust C bindings, .NET (the runtime bundles unpatched Brotli 1.1.0) and Brotli4j.

### **📍 Call Sites**
Direct decoder calls such as `zlib.brotliDecompress*`, `createBrotliDecompress` and `brotli.decompress` are listed so you can fix the code that handles untrusted data first.

## 🖥️ Example Output

```text
== Node.js version pins in the repository ==
  [VULN] Node.js 24.16.0-slim bundles a vulnerable Brotli decoder (fixed in 24.22.1)
         at:  Dockerfile:2 (FROM node:24.16.0-slim)
         fix: use 'FROM node:24.22.1-slim' in Dockerfile:2 and rebuild/redeploy the image
  [OK]   Node.js 26.12.1 is patched
         at:  docker-compose.yml:5 (image node:26.12.1)

== Python dependencies ==
  [VULN] Brotli 1.2.0 bundles the vulnerable Brotli decoder (fixed in 1.2.1)
         at:  services/api/poetry.lock
         fix: poetry add "Brotli>=1.2.1" (or 'poetry update brotli' if transitive) and commit poetry.lock
  [WARN] brotlicffi constraint '>=1.0.9.2' still allows vulnerable versions
         at:  services/api/requirements.txt
         fix: raise the constraint to "brotlicffi>=1.2.1.0" in services/api/requirements.txt and regenerate the lockfile

== Native binaries in the repository (node_modules, virtualenvs, vendored libs) ==
  [VULN] native binary contains an unpatched Brotli C decoder (libbrotlidec.1.1.0.dylib)
         at:  .venv/lib/python3.12/site-packages/PIL/.dylibs/libbrotlidec.1.1.0.dylib
         fix: upgrade the Python package 'Pillow' to a release that bundles Brotli >= 1.2.1: pip install -U Pillow (re-run this script to verify; uninstall it if unused)

== Summary ==
  3 vulnerable, 1 warning(s)

Suggested fixes
  1. use 'FROM node:24.22.1-slim' in Dockerfile:2 and rebuild/redeploy the image
  ...
```

Findings are marked **VULN** (vulnerable component found), **WARN** (may be vulnerable or needs a decision), **INFO** (context or exposure path) or **OK** (verified patched). The summary ends with a de-duplicated list of fixes, what to do after upgrading, and stopgaps for when you can't upgrade yet.

## 🛠️ Fixing What It Finds

- **Node.js**: upgrade to 22.23.4, 24.22.1 or 26.12.1 (`nvm install 24.22.1`, `FROM node:24.22.1-slim`). Node.js has no workaround; upgrading the runtime is the only complete fix.
- **Python**: `pip install -U "Brotli>=1.2.1" "brotlicffi>=1.2.1.0"`, then raise the constraint and regenerate `poetry.lock` / `uv.lock` / `requirements.txt`. As a stopgap, uninstall Brotli and brotlicffi; urllib3, requests and aiohttp fall back to gzip/deflate.
- **System library**: install your distribution's security update, then restart every process that uses it.
- **Vendored copies**: update to Brotli 1.0.10 / 1.1.1 / 1.2.1 or cherry-pick commit `0ed4268`, then rebuild.
- **Inbound traffic**: reject request bodies with `Content-Encoding: br` at your proxy, load balancer or WAF.

After upgrading, restart every process, rebuild every image (`docker build --pull`) and commit the updated lockfiles. Check everywhere code runs: production, staging, CI runners, build images, serverless runtimes and developer laptops.

## 🔄 CI/CD Integration

### **GitHub Actions**
```yaml
name: Broccoli2Shell scan
on: [push, pull_request]
jobs:
  broccoli2shell:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan repository for CVE-2026-111497
        run: |
          curl -fsSL -o broccoli2shell-detect.sh https://raw.githubusercontent.com/knostic/open-tools/main/Broccoli2Shell_detector/broccoli2shell-detect.sh
          bash broccoli2shell-detect.sh --no-system --no-color
```

Use `--strict` to also fail the build on warnings, such as floating `node:24` image tags. To fix the script's version, pin a commit SHA instead of `main`.

## ⚠️ Limitations

- **Version data**: fixed versions and "not fixed yet" projects reflect the [broccoli2shell.com](https://broccoli2shell.com) advisory as of **26 October 2026**. .NET, DuckDB, pyarrow and others had no fixed release at that time.
- **Binary check**: a decoder built without its error-message strings isn't detected. It also won't be reported as vulnerable by mistake.
- **No fixed version known**: for Go `andybalholm/brotli` and Brotli4j the advisory names no fixed version, so the script tells you to update to the latest release.
- **Docker images**: images aren't pulled or inspected. Check one with `docker run --rm --entrypoint node <image> --version` and `docker run --rm --entrypoint pip <image> show Brotli brotlicffi`.
- **Exposure paths**: Express, body-parser and the Python HTTP clients are reported as context. Upgrading them doesn't fix the bug; the runtime or Brotli package does.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

**DISCLAIMER OF LIABILITY**

KNOSTIC PROVIDES THIS BROCCOLI2SHELL DETECTOR SCRIPT AS-IS FOR EDUCATIONAL AND SECURITY ASSESSMENT PURPOSES. BY DOWNLOADING, EXAMINING, OR EXECUTING THIS SCRIPT, YOU ACKNOWLEDGE AND AGREE THAT: (1) YOU HAVE THOROUGHLY REVIEWED THE SOURCE CODE AND UNDERSTAND ITS FUNCTIONALITY AND POTENTIAL RISKS; (2) YOU ARE SOLELY RESPONSIBLE FOR ANY CONSEQUENCES, DAMAGES, OR DATA LOSS THAT MAY RESULT FROM RUNNING THIS SCRIPT; (3) KNOSTIC DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT; (4) KNOSTIC SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING FROM YOUR USE OF THIS SCRIPT, REGARDLESS OF THE LEGAL THEORY UNDER WHICH SUCH LIABILITY IS ASSERTED; AND (5) YOU ASSUME ALL RISKS ASSOCIATED WITH THE SCRIPT'S EXECUTION, INCLUDING BUT NOT LIMITED TO SYSTEM MODIFICATIONS, FILE DELETIONS, AND POTENTIAL SECURITY IMPLICATIONS. THIS SCRIPT IS PROVIDED "AS-IS" WITHOUT ANY GUARANTEE OF ACCURACY, COMPLETENESS, OR SAFETY. USE AT YOUR OWN RISK AND DISCRETION.
