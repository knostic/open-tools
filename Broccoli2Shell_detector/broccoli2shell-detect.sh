#!/usr/bin/env bash
#
# broccoli2shell-detect.sh
#
# Detects exposure to CVE-2026-111497 ("Broccoli2Shell"): an out-of-bounds
# write in Google's reference Brotli C decoder (1.0.3 through 1.2.0) that a
# crafted Brotli stream can turn into a crash, memory leak or code execution.
# Fixed upstream in Brotli 1.0.10 / 1.1.1 / 1.2.1 (google/brotli 0ed4268).
# Details: https://broccoli2shell.com
#
# Scans the git repository in the target directory (default: .) for Node.js,
# Python and vendored/native Brotli decoders and, unless --no-system is given,
# the Node.js and Python runtimes, Python virtualenvs (Poetry, pipx, uv tools,
# pipenv, virtualenvwrapper) and Brotli libraries on this machine.
# Every finding comes with a suggested fix.
#
# Read-only: nothing is installed or changed, and no code from the scanned
# repository is run. Only the installed tools' own version and metadata
# commands run (node --version / -p with NODE_OPTIONS cleared, python -I,
# bun / envoy / curl --version, brew, dpkg, rpm, apk, php, gem). Note that
# python -I still processes .pth files in the interpreter's site-packages.
#
# How it detects the vulnerability
#   Patched code is recognised in two ways: by version numbers, and by the
#   fix itself, which adds a new decoder error code, BLOCK_SWITCH (-17).
#
#   Node.js       Node bundles its own Brotli, so only the Node version
#                 matters: < 22.23.4, < 24.22.1, < 26.12.1 and every
#                 end-of-life line (<= 21, 23, 25) are vulnerable. Checked in
#                 .nvmrc, .node-version, .tool-versions, package.json
#                 (volta/engines), Dockerfile FROM node:<tag>, image: tags in
#                 YAML, GitHub Actions node-version, the node on PATH and
#                 installs from nvm, fnm, volta, asdf, mise, n and Homebrew.
#                 Lockfiles and node_modules are searched for iltorb (bundles
#                 an old decoder) and for Express 5.0-5.3 / body-parser
#                 2.0-2.3, which decode br request bodies (exposure paths).
#   Bun           1.0.21 - 1.4.3 are vulnerable, fixed in 1.4.4. Checked in
#                 .bun-version, .tool-versions, package.json packageManager,
#                 FROM/image oven/bun:<tag>, GitHub Actions bun-version and
#                 the bun on PATH / in ~/.bun.
#   Envoy, Istio  Envoy < 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0 and
#                 Istio < 1.29.9 / 1.30.6 / 1.31.2 (per release line) in
#                 envoyproxy/envoy* and istio/proxyv2|pilot|ztunnel images
#                 and the envoy on PATH. Proxies only decode Brotli when a
#                 Brotli decompressor filter is configured, so outdated
#                 versions are VULN when the repo configures one
#                 (envoy.extensions.compression.brotli.decompressor), WARN
#                 otherwise.
#   curl          curl decodes Brotli only with --compressed and only when
#                 built with Brotli ("brotli" in curl -V Features); a
#                 statically linked decoder gets the binary check below.
#   Python        PyPI Brotli 1.0.3 - 1.2.0 (fixed in 1.0.10 / 1.1.1 /
#                 1.2.1) and brotlicffi 1.0.3 - 1.2.0.x (fixed in 1.2.1.0)
#                 compile the vulnerable decoder. Checked in requirements*.txt/.in,
#                 pyproject.toml, setup.cfg/.py, Pipfile(.lock), poetry.lock,
#                 uv.lock, pdm.lock and conda environment files (pins and
#                 constraints that still allow or force a vulnerable
#                 release), in *.dist-info of virtualenvs inside the repo, in
#                 every Python interpreter on PATH / pyenv / conda (and its
#                 user site directory), and in
#                 Poetry, pipx, uv tool, pipenv and virtualenvwrapper envs.
#   System lib    libbrotlidec from apt/dpkg (changelog mentions the CVE?),
#                 rpm, apk, Homebrew and MacPorts, compared against the fixed
#                 upstream releases 1.0.10 / 1.1.1 / 1.2.1 (affected range:
#                 1.0.3 - 1.2.0). On Linux, processes that still map an old
#                 (deleted) libbrotlidec are listed for a restart.
#   Binaries      Every Brotli decoder contains the string
#                 "_ERROR_FORMAT_EXUBERANT_NIBBLE" (from
#                 BrotliDecoderErrorString); only patched ones also contain
#                 "_ERROR_FORMAT_BLOCK_SWITCH". .node/.so/.dylib/.pyd/.dll/.a
#                 files in the repo, wheels (e.g. Pillow's bundled
#                 libbrotlidec) and system libraries are checked for both, so
#                 vendored or statically linked copies are found whatever
#                 their version label says.
#   C sources     Vendored decode.h files are patched if they define the
#                 BLOCK_SWITCH error code; CMake/meson/conan/vcpkg/bazel and
#                 .gitmodules references to google/brotli are version-checked.
#   Others        Ruby brotli gem < 0.9.1, PHP brotli extension < 0.21.1,
#                 Go andybalholm/brotli < v1.2.7, cbrotli, Rust C bindings, .NET
#                 projects (runtime fixed in 8.0.33 / 9.0.22 / 10.0.14 /
#                 11.0.0-rc.3), pyarrow/duckdb (unpatched bundled copies),
#                 Brotli4j.
#   Call sites    Direct decoder calls (zlib.brotliDecompress*,
#                 brotli.decompress, ...) and curl --compressed /
#                 CURLOPT_ACCEPT_ENCODING uses are listed to help prioritise.
#
#   Levels: VULN = vulnerable component found, WARN = may be vulnerable or
#   needs a decision, INFO = context / exposure path, OK = verified patched.
#
# Usage: broccoli2shell-detect.sh [options] [dir]
#   --no-system    scan the repository only
#   --no-binaries  skip scanning native binaries for an embedded decoder
#   --strict       also exit 1 when only warnings were found
#   --no-color     disable colored output
#   -h, --help     show this help
#
# Exit status: 0 nothing vulnerable found, 1 vulnerable component found (or
# any warning with --strict), 2 usage error.

CVE="CVE-2026-111497"
NODE_DEFAULT_TARGET="24.22.1"
PY_BROTLI_FIX="1.2.1"
PY_BROTLICFFI_FIX="1.2.1.0"
RUBY_BROTLI_FIX="0.9.1"
PHP_BROTLI_FIX="0.21.1"
GO_BROTLI_FIX="v1.2.7"
DOTNET_FIXES="8.0.33 / 9.0.22 / 10.0.14 (11.0.0-rc.3)"
UPSTREAM_FIXES="1.0.10 / 1.1.1 / 1.2.1"
# BrotliDecoderErrorString() compiles every error-code name into the decoder.
# The first string is present in all decoders, the second one only in patched
# decoders (the fix adds error code -17, BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH).
DECODER_MARKER="_ERROR_FORMAT_EXUBERANT_NIBBLE"
PATCH_MARKER="_ERROR_FORMAT_BLOCK_SWITCH"

SCAN_SYSTEM=1
SCAN_BINARIES=1
STRICT=0
USE_COLOR=1
TARGET="."

usage() { sed -n '3,/^$/p' "$0" | sed -E 's/^# ?//'; }

while [ $# -gt 0 ]; do
  case $1 in
    --no-system) SCAN_SYSTEM=0 ;;
    --no-binaries) SCAN_BINARIES=0 ;;
    --strict) STRICT=1 ;;
    --no-color) USE_COLOR=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) TARGET=$1 ;;
  esac
  shift
done

ROOT=$(cd "$TARGET" 2>/dev/null && pwd -P) || { echo "not a directory: $TARGET" >&2; exit 2; }

if [ "$USE_COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[1;31m' C_YELLOW=$'\033[1;33m' C_GREEN=$'\033[32m' C_BLUE=$'\033[36m'
  C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_RESET=$'\033[0m'
else
  C_RED='' C_YELLOW='' C_GREEN='' C_BLUE='' C_BOLD='' C_DIM='' C_RESET=''
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/broccoli2shell.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT
FIX_FILE="$WORK/fixes"
: > "$FIX_FILE"
VULN_COUNT=0
WARN_COUNT=0
SEEN=$'\n'
PY_VULN_FOUND=0
PY_CLIENTS=""

# ---------------------------------------------------------------- helpers ---

section() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_RESET"; }

# report LEVEL MESSAGE [LOCATION] [FIX]
report() {
  local level=$1 msg=$2 where=$3 fix=$4 color
  case $level in
    VULN) VULN_COUNT=$((VULN_COUNT + 1)); color=$C_RED ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)); color=$C_YELLOW ;;
    OK)   color=$C_GREEN ;;
    *)    color=$C_BLUE ;;
  esac
  printf '  %s%-6s%s %s\n' "$color" "[$level]" "$C_RESET" "$msg"
  [ -n "$where" ] && printf '         %sat:%s  %s\n' "$C_DIM" "$C_RESET" "$where"
  if [ -n "$fix" ]; then
    printf '         %sfix:%s %s\n' "$C_BOLD" "$C_RESET" "$fix"
    case $level in VULN|WARN) printf '%s\n' "$fix" >> "$FIX_FILE" ;; esac
  fi
}

# seen_once KEY: succeeds only the first time KEY is passed
seen_once() {
  case $SEEN in *$'\n'"$1"$'\n'*) return 1 ;; esac
  SEEN="$SEEN$1"$'\n'
}

relpath() {
  case $1 in
    "$ROOT"/*) printf '%s' "${1#"$ROOT"/}" ;;
    *) printf '%s' "$1" ;;
  esac
}

resolve_path() {
  realpath "$1" 2>/dev/null || readlink -f "$1" 2>/dev/null || printf '%s' "$1"
}

# First dotted number in a string: "v24.16.0-slim" -> "24.16.0"
clean_ver() {
  printf '%s' "$1" | sed -nE 's/^[^0-9]*([0-9]+(\.[0-9]+)*).*/\1/p'
}

# ver_cmp A B prints -1, 0 or 1 (numeric, dot separated, missing parts = 0)
ver_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    n = split(a, x, "."); m = split(b, y, "."); k = (n > m ? n : m)
    for (i = 1; i <= k; i++) {
      xi = (i <= n ? x[i] + 0 : 0); yi = (i <= m ? y[i] + 0 : 0)
      if (xi < yi) { print -1; exit }
      if (xi > yi) { print 1; exit }
    }
    print 0 }'
}
ver_lt() { [ "$(ver_cmp "$1" "$2")" = "-1" ]; }

# Status of an upstream Brotli C version: vuln | ok | old (predates the bug)
brotli_c_status() {
  local v=$1
  if ver_lt "$v" 1.0.3; then echo old
  elif ver_lt "$v" 1.0.10; then echo vuln
  elif ver_lt "$v" 1.1.0; then echo ok
  elif ver_lt "$v" 1.1.1; then echo vuln
  elif ver_lt "$v" 1.2.0; then echo ok
  elif ver_lt "$v" 1.2.1; then echo vuln
  else echo ok
  fi
}

# Runtimes and proxies that bundle their own Brotli decoder, by release line.
# Fixed versions follow the Wiz advisory: Node.js 22.23.4 / 24.22.1 / 26.12.1,
# Bun 1.4.4 (affected 1.0.21-1.4.3), Envoy 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 /
# 1.40.0, Istio 1.29.9 / 1.30.6 / 1.31.2.

# product_fix PRODUCT LINE: first patched version on release LINE, empty if none
product_fix() {
  case $1:$2 in
    node:22) echo 22.23.4 ;;
    node:24) echo 24.22.1 ;;
    node:26) echo 26.12.1 ;;
    bun:*) echo 1.4.4 ;;
    envoy:1.36) echo 1.36.12 ;;
    envoy:1.37) echo 1.37.8 ;;
    envoy:1.38) echo 1.38.6 ;;
    envoy:1.39) echo 1.39.3 ;;
    envoy:1.40) echo 1.40.0 ;;
    istio:1.29) echo 1.29.9 ;;
    istio:1.30) echo 1.30.6 ;;
    istio:1.31) echo 1.31.2 ;;
  esac
}

product_name() { case $1 in node) echo Node.js ;; bun) echo Bun ;; envoy) echo Envoy ;; istio) echo Istio ;; esac; }
# newest release line covered by the advisories
product_newest_line() { case $1 in node) echo 26 ;; envoy) echo 1.40 ;; istio) echo 1.31 ;; esac; }
# version to suggest for lines without a fix
product_default_target() { case $1 in node) echo "$NODE_DEFAULT_TARGET" ;; bun) echo 1.4.4 ;; envoy) echo 1.40.0 ;; istio) echo 1.31.2 ;; esac; }
# version components that name a release line: Node.js "24", Envoy/Istio "1.38"; Bun has a single line
product_line_parts() { case $1 in node) echo 1 ;; envoy|istio) echo 2 ;; *) echo 0 ;; esac; }

product_line() {
  local n
  n=$(product_line_parts "$1")
  [ "$n" -gt 0 ] && printf '%s' "$2" | cut -d. -f1-"$n"
}

# product_line_kind PRODUCT LINE: supported | newer | eol
product_line_kind() {
  if [ -n "$(product_fix "$1" "$2")" ]; then echo supported
  elif ver_lt "$(product_newest_line "$1")" "$2"; then echo newer
  else echo eol
  fi
}

product_target() {
  local t
  t=$(product_fix "$1" "$2")
  echo "${t:-$(product_default_target "$1")}"
}

# product_status PRODUCT X.Y.Z: ok | vuln | eol | old (predates the affected releases)
product_status() {
  local p=$1 v line
  v=$(clean_ver "$2"); line=$(product_line "$p" "$v")
  if [ "$p" = bun ] && ver_lt "$v" 1.0.21; then echo old; return; fi
  case $(product_line_kind "$p" "$line") in
    supported) if ver_lt "$v" "$(product_fix "$p" "$line")"; then echo vuln; else echo ok; fi ;;
    newer) echo ok ;;
    *) echo eol ;;
  esac
}

node_status() { product_status node "$1"; }

# Does FILE contain a Brotli decoder? prints patched | vulnerable | none
binary_decoder_state() {
  if ! LC_ALL=C grep -a -q -F "$DECODER_MARKER" "$1" 2>/dev/null; then echo none
  elif LC_ALL=C grep -a -q -F "$PATCH_MARKER" "$1" 2>/dev/null; then echo patched
  else echo vulnerable
  fi
}

# binary_owner_fix PATH [UPGRADE_TEMPLATE]: fix hint for a native binary, based
# on which package ships it. UPGRADE_TEMPLATE is the upgrade command for the
# environment the binary lives in, with @PKG@ standing for the package name.
binary_owner_fix() {
  local p=$1 tmpl=${2:-"pip install -U @PKG@"} pkg
  case $p in
    */site-packages/*|*/dist-packages/*)
      pkg=${p##*-packages/}; pkg=${pkg%%/*}
      case $pkg in
        PIL|pillow.libs|Pillow.libs) pkg=Pillow ;;
        _brotli*) pkg=Brotli ;;
        *.libs|*.dylibs) pkg=${pkg%.*} ;;
      esac
      echo "upgrade the Python package '$pkg' to a release that bundles Brotli >= $PY_BROTLI_FIX: ${tmpl//@PKG@/$pkg} (re-run this script to verify; uninstall it if unused)"
      ;;
    */node_modules/*)
      pkg=${p##*/node_modules/}
      case $pkg in @*/*) pkg=$(printf '%s' "$pkg" | cut -d/ -f1-2) ;; *) pkg=${pkg%%/*} ;; esac
      echo "update and rebuild the npm package '$pkg' (npm update $pkg && npm rebuild $pkg) to one that bundles Brotli $UPSTREAM_FIXES"
      ;;
    *)
      echo "rebuild or update this binary against Brotli $UPSTREAM_FIXES (or cherry-pick google/brotli commit 0ed4268), then restart anything that loads it"
      ;;
  esac
}

# native_decoder_files DIR...: native libraries under DIR that embed a Brotli decoder
native_decoder_files() {
  find "$@" -type f \( -name '*.so' -o -name '*.so.*' -o -name '*.dylib' -o -name '*.pyd' -o -name '*.node' \) \
    -size -300M -print0 2>/dev/null | xargs -0 grep -a -l -F "$DECODER_MARKER" 2>/dev/null
}

# check_binary FILE LABEL [UPGRADE_TEMPLATE]; each file is reported once even
# if several scans (repo, interpreters, virtualenvs) reach it.
check_binary() {
  local f=$1 label=$2 tmpl=$3 state hint=""
  seen_once "bin:$(resolve_path "$f")" || return 0
  state=$(binary_decoder_state "$f")
  case $(basename "$f") in
    libbrotlidec*) hint=" ($(basename "$f"))" ;;
  esac
  case $state in
    vulnerable)
      case $(basename "$f") in _brotli*|*brotlicffi*) PY_VULN_FOUND=1 ;; esac
      report VULN "$label contains an unpatched Brotli C decoder$hint" "$(relpath "$f")" "$(binary_owner_fix "$f" "$tmpl")" ;;
    patched) report OK "$label contains a patched Brotli decoder$hint" "$(relpath "$f")" ;;
  esac
}

# ------------------------------------------------------- file inventory ---

# All candidate manifest files in the repository, skipping dependency and
# virtualenv directories (those are scanned separately).
find "$ROOT" \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name .tox -o -name .nox \
    -o -name site-packages -o -name __pycache__ -o -name .mypy_cache -o -name .pytest_cache -o -name .terraform \) -prune \
  -o -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock \
    -o -name pnpm-lock.yaml -o -name bun.lock -o -name .nvmrc -o -name .node-version -o -name .bun-version -o -name .tool-versions \
    -o -name 'Dockerfile*' -o -name '*.dockerfile' -o -name 'Containerfile*' -o -name '*.yml' -o -name '*.yaml' \
    -o -name '*requirements*.txt' -o -name '*requirements*.in' -o -name 'constraints*.txt' -o -path '*/requirements/*.txt' \
    -o -name pyproject.toml -o -name setup.cfg -o -name setup.py -o -name Pipfile -o -name Pipfile.lock \
    -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Gemfile.lock -o -name go.mod -o -name Cargo.lock \
    -o -name '*.csproj' -o -name '*.fsproj' -o -name '*.vbproj' -o -name pom.xml -o -name build.gradle \
    -o -name build.gradle.kts -o -name composer.json -o -name .gitmodules -o -name CMakeLists.txt -o -name '*.cmake' \
    -o -name meson.build -o -name conanfile.txt -o -name conanfile.py -o -name vcpkg.json -o -name MODULE.bazel \
    -o -name WORKSPACE -o -name '*.bzl' \) -print 2>/dev/null | sort > "$WORK/manifests"

# manifests_matching REGEX: manifest paths whose basename matches REGEX
manifests_matching() {
  RE="$1" awk '{ n = $0; sub(/.*\//, "", n); if (n ~ ENVIRON["RE"]) print }' "$WORK/manifests"
}

# ---------------------------------------------- runtime and image pins ---

# eval_runtime_spec PRODUCT SPEC LOCATION FIX_TEMPLATE [CAP] [NOTE]
# FIX_TEMPLATE may contain @V@, replaced by the patched version to use.
# CAP=WARN downgrades findings (CI test matrices, proxies without a Brotli
# decompressor); NOTE is appended to VULN/WARN messages.
eval_runtime_spec() {
  local p=$1 raw=$2 where=$3 tmpl=$4 cap=$5 note=$6 name s v line kind target parts lparts lvl floatmsg
  name=$(product_name "$p")
  s=$(printf '%s' "$raw" | tr -d "\"' \r" | tr 'A-Z' 'a-z')
  lvl=VULN; [ "$cap" = WARN ] && lvl=WARN
  floatmsg="$name '$raw' floats; it is only safe if it resolved to a patched release when installed/built$note"
  if [ "$p" = node ]; then
    s=${s#lts/}
    case $s in
      argon*|boron*|carbon*|dubnium*|erbium*|fermium*|gallium*|hydrogen*|iron*)
        report $lvl "Node.js '$raw' is an end-of-life line with no patched release" "$where" "${tmpl//@V@/$NODE_DEFAULT_TARGET}"
        return ;;
      jod*) s=22 ;;
      krypton*) s=24 ;;
    esac
  fi
  case $s in
    *'$'*|*'{{'*) report INFO "$name version '$raw' is templated; could not evaluate" "$where"; return ;;
    ''|latest*|current*|node|stable|lts|lts-*|'*'|canary*|dev|dev-*|*-dev|*-dev-*)
      report WARN "$floatmsg" "$where" \
        "reinstall / rebuild with --pull so it resolves to a patched release, or pin it: ${tmpl//@V@/$(product_default_target "$p")}"
      return ;;
    *'>'*|*'<'*|*'^'*|*'~'*|*'||'*)
      report INFO "$name range '$raw' (engines-style) does not choose the version that runs; make sure that one is patched" "$where"
      return ;;
  esac
  v=$(spec_version "$s")
  if [ -z "$v" ]; then
    # tags such as "alpine3.20", "slim" or "distroless" track the latest release
    report WARN "$floatmsg" "$where" \
      "reinstall / rebuild with --pull so it resolves to a patched release, or pin it: ${tmpl//@V@/$(product_default_target "$p")}"
    return
  fi
  parts=$(printf '%s' "$v" | awk -F. '{print NF}')
  lparts=$(product_line_parts "$p")
  if [ "$parts" -ge 3 ]; then
    line=$(product_line "$p" "$v"); target=$(product_target "$p" "$line")
    case $(product_status "$p" "$v") in
      ok) if [ "$(product_line_kind "$p" "$line")" = newer ]; then
            report OK "$name $raw is newer than every affected release line" "$where"
          else
            report OK "$name $raw is patched" "$where"
          fi ;;
      old) report OK "$name $raw predates the affected releases" "$where" ;;
      vuln) report $lvl "$name $raw bundles a vulnerable Brotli decoder (fixed in $target)$note" "$where" "${tmpl//@V@/$target}" ;;
      *) report $lvl "$name $raw is an end-of-life line; no patched release exists$note" "$where" "${tmpl//@V@/$target}" ;;
    esac
    return
  fi
  if [ "$parts" -lt "$lparts" ]; then
    report WARN "$floatmsg" "$where" \
      "reinstall / rebuild with --pull so it resolves to a patched release, or pin it: ${tmpl//@V@/$(product_default_target "$p")}"
    return
  fi
  line=$(product_line "$p" "$v"); kind=$(product_line_kind "$p" "$line"); target=$(product_target "$p" "$line")
  if [ "$kind" = newer ]; then
    report OK "$name $raw is newer than every affected release line" "$where"
  elif [ "$kind" = eol ]; then
    report $lvl "$name $raw is an end-of-life line; no patched release exists$note" "$where" "${tmpl//@V@/$target}"
  elif [ "$parts" -gt "$lparts" ] && ! ver_lt "$v.0" "$target"; then
    report OK "$name $v.x is patched" "$where"
  elif [ "$parts" -gt "$lparts" ] && ver_lt "$v.99999" "$target"; then
    report $lvl "$name $v.x never receives the fix (fixed in $target)$note" "$where" "${tmpl//@V@/$target}"
  else
    report WARN "$name '$raw' floats within a supported line; safe only if resolved to >= $target when installed/built$note" "$where" \
      "reinstall / rebuild with --pull so it resolves to >= $target, or pin it: ${tmpl//@V@/$target}"
  fi
}

# Product version carried by a version spec or image tag, empty when it floats.
# Only a leading version ("24.16.0-alpine3.20", "v1.38.5") or a trailing one after
# a variant prefix ("distroless-v1.38.5") counts; "alpine3.20" is a distro version.
spec_version() {
  case $1 in
    [0-9]*|v[0-9]*) clean_ver "$1" ;;
    *-[0-9]*|*-v[0-9]*) printf '%s' "$1" | sed -nE 's/^.*-v?([0-9]+(\.[0-9]+)+)$/\1/p' ;;
  esac
}

# Image tag with its version replaced by @V@, keeping prefixes and variants:
# "24.16.0-slim" -> "@V@-slim", "24-alpine3.20" -> "@V@-alpine3.20", "v1.38.5" -> "v@V@",
# "distroless-v1.38.5" -> "distroless-v@V@", "lts-alpine3.21" / "hydrogen-alpine3.21" ->
# "@V@-alpine3.21", "bookworm-slim" -> "@V@-bookworm-slim", "canary" / "dev-4f3a9c2" -> "@V@"
image_tag_template() {
  local t=$1 r
  case $t in
    [0-9]*|v[0-9]*) printf '%s' "$t" | sed -E 's/^(v?)[0-9]+(\.[0-9]+)*/\1@V@/'; return ;;
  esac
  r=$(printf '%s' "$t" | sed -nE 's/^(.*-)(v?)[0-9]+(\.[0-9]+)+$/\1\2@V@/p')
  if [ -n "$r" ]; then printf '%s' "$r"; return; fi
  # drop channel aliases and Node.js LTS codenames, keep the distro variant
  r=$(printf '%s-' "$t" | sed -E 's/^((lts|latest|current|stable|canary|argon|boron|carbon|dubnium|erbium|fermium|gallium|hydrogen|iron|jod|krypton)-)+//; s/-$//')
  case $r in
    alpine*|slim*|bookworm*|bullseye*|buster*|trixie*|distroless*|debian*) printf '@V@-%s' "$r" ;;
    *) printf '@V@' ;;
  esac
}

# Product shipped in a container image repository, if it is one we track
image_product() {
  case $1 in
    node|*/node) echo node ;;
    oven/bun|*/oven/bun) echo bun ;;
    *envoyproxy/envoy|*envoyproxy/envoy-*) echo envoy ;;
    *istio*/proxyv2|*istio*/pilot|*istio*/ztunnel|*istio*/install-cni) echo istio ;;
  esac
}

# Envoy and Istio only decode Brotli when a Brotli decompressor filter is configured
PROXY_DECOMPRESSOR_HITS=""
proxy_note() {
  if [ -n "$PROXY_DECOMPRESSOR_HITS" ]; then
    echo ""
  else
    echo " (only reachable if a Brotli decompressor filter is configured; none found in this repo)"
  fi
}

# eval_image REL LINE REPOSITORY TAG KIND: KIND is "FROM" (Dockerfile) or "image" (YAML)
eval_image() {
  local rel=$1 line=$2 repo=$3 tag=$4 kind=$5 p cap="" note="" tmpl
  p=$(image_product "$repo")
  [ -n "$p" ] || return 1
  if [ "$tag" = digest ]; then
    report INFO "$repo image pinned by digest; check the $(product_name "$p") version inside it" "$rel:$line"
    return 0
  fi
  case $p in envoy|istio) note=$(proxy_note); [ -n "$note" ] && cap=WARN ;; esac
  tmpl=$(image_tag_template "$tag")
  # Envoy image tags carry a "v" prefix (v1.40.0)
  case $p:$tmpl in envoy:@V@*) tmpl="v$tmpl" ;; esac
  if [ "$kind" = FROM ]; then
    eval_runtime_spec "$p" "$tag" "$rel:$line (FROM $repo:$tag)" "use 'FROM $repo:$tmpl' in $rel:$line and rebuild/redeploy the image" "$cap" "$note"
  else
    eval_runtime_spec "$p" "$tag" "$rel:$line (image $repo:$tag)" "use image $repo:$tmpl in $rel:$line and redeploy" "$cap" "$note"
  fi
  return 0
}

# Splits an image reference (field 2 of the input) into repository and tag;
# prints "line<TAB>repository<TAB>tag" (tag "digest" when pinned by digest).
IMAGE_SPLIT_AWK='
  function emit(line, img,   n, p, last, prefix, name, tag) {
    n = split(img, p, "/"); last = p[n]; prefix = substr(img, 1, length(img) - length(last))
    name = last; tag = "latest"
    if (index(last, "@")) { name = substr(last, 1, index(last, "@") - 1); sub(/:.*/, "", name); tag = "digest" }
    else if (index(last, ":")) { name = substr(last, 1, index(last, ":") - 1); tag = substr(last, index(last, ":") + 1) }
    print line "\t" prefix name "\t" tag
  }'

dockerfile_images() {
  awk "$IMAGE_SPLIT_AWK"'
    toupper($1) == "ARG" { split($2, kv, "="); if (kv[2] != "") { v = kv[2]; gsub(/["\047]/, "", v); args[kv[1]] = v } }
    toupper($1) == "FROM" {
      i = 2; if ($i ~ /^--platform=/) i++
      img = $i
      for (a in args) { gsub("\\$\\{" a "\\}", args[a], img); gsub("\\$" a, args[a], img) }
      emit(NR, img)
    }' "$1"
}

yaml_images() {
  awk "$IMAGE_SPLIT_AWK"'
    /^[[:space:]]*-?[[:space:]]*image:[[:space:]]*[^[:space:]{|>]/ {
      v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); sub(/[[:space:]]+#.*/, "", v); gsub(/["\047[:space:]]/, "", v)
      if (v != "") emit(NR, v)
    }' "$1"
}

check_version_pins() {
  section "Runtime and proxy version pins in the repository (Node.js, Bun, Envoy, Istio)"
  local f rel base spec line repo tag p found=0
  PROXY_DECOMPRESSOR_HITS=$(grep -rnE --exclude-dir=node_modules --exclude-dir=.git \
      --include='*.yaml' --include='*.yml' --include='*.json' --include='*.tpl' \
      'compression\.brotli\.decompressor|brotli\.decompressor\.v3' "$ROOT" 2>/dev/null)
  while IFS= read -r f; do
    rel=$(relpath "$f"); base=$(basename "$f")
    case $base in
      .nvmrc|.node-version|.bun-version)
        spec=$(sed -n '/[^[:space:]]/{p;q;}' "$f" | tr -d '[:space:]')
        [ -n "$spec" ] || continue
        found=1
        if [ "$base" = .bun-version ]; then
          eval_runtime_spec bun "$spec" "$rel" "set $base to @V@ and upgrade Bun (bun upgrade)"
        else
          eval_runtime_spec node "$spec" "$rel" "set $base to @V@ and reinstall (nvm install / fnm install)"
        fi
        ;;
      .tool-versions)
        while read -r p spec; do
          found=1
          eval_runtime_spec $p "$spec" "$rel" "set '$p @V@' in $rel and run asdf/mise install"
        done < <(awk '($1 == "nodejs" || $1 == "node") && $2 != "" { print "node", $2 } $1 == "bun" && $2 != "" { print "bun", $2 }' "$f")
        ;;
      package.json)
        while IFS= read -r spec; do
          found=1
          eval_runtime_spec node "$spec" "$rel (\"node\": \"$spec\")" "set the Node.js pin in $rel (volta/engines) to @V@"
        # only version-like values: "exports"/"imports" also use a "node" key for paths
        done < <(grep -Eo '"node"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" | sed -E 's/.*"([^"]+)"$/\1/' |
                 grep -Ei '^([v0-9<>=^~*. x|-]+|lts.*|latest|current|stable)$')
        while IFS= read -r spec; do
          found=1
          eval_runtime_spec bun "$spec" "$rel (\"packageManager\": \"bun@$spec\")" "set \"packageManager\": \"bun@@V@\" in $rel and upgrade Bun (bun upgrade)"
        done < <(grep -Eo '"packageManager"[[:space:]]*:[[:space:]]*"bun@[^"+]+' "$f" | sed -E 's/.*bun@//')
        ;;
      Dockerfile*|*.dockerfile|Containerfile*)
        while IFS=$'\t' read -r line repo tag; do
          eval_image "$rel" "$line" "$repo" "$tag" FROM && found=1
        done < <(dockerfile_images "$f")
        ;;
      *.yml|*.yaml)
        # container images (compose, k8s, GitLab, CircleCI)
        while IFS=$'\t' read -r line repo tag; do
          eval_image "$rel" "$line" "$repo" "$tag" image && found=1
        done < <(yaml_images "$f")
        # GitHub Actions setup-node / setup-bun versions and matrices
        case $f in
          */.github/workflows/*)
            while IFS=$'\t' read -r line p spec; do
              found=1
              eval_runtime_spec "$p" "$spec" "$rel:$line (CI)" "use $p-version @V@ in $rel:$line" WARN
            done < <(awk '
              /^[[:space:]]*-?[[:space:]]*(node-version|node_version|node|bun-version|bun_version)[[:space:]]*:[[:space:]]*[^[:space:]]/ {
                k = $0; sub(/^[[:space:]]*-?[[:space:]]*/, "", k); sub(/[-_[:space:]:].*/, "", k)
                v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); sub(/[[:space:]]+#.*/, "", v)
                if (v ~ /\$\{\{/) next
                gsub(/[][]/, "", v); n = split(v, a, ",")
                for (i = 1; i <= n; i++) { x = a[i]; gsub(/[[:space:]"\047]/, "", x); sub(/\.x$/, "", x); if (x != "") print NR "\t" k "\t" x }
              }' "$f")
            ;;
        esac
        ;;
    esac
  done < "$WORK/manifests"
  [ "$found" = 1 ] || report INFO "no Node.js, Bun, Envoy or Istio version pins found (.nvmrc, .bun-version, .tool-versions, Dockerfile, YAML, CI)" ""

  # Envoy / Istio configuration that makes the proxy decode Brotli
  local hit
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    report WARN "Envoy Brotli decompressor filter configured: Envoy/Istio proxies using it decode attacker-supplied Brotli" \
      "$(relpath "${hit%%:*}"):$(printf '%s' "$hit" | cut -d: -f2)" \
      "run patched proxies (Envoy 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0, Istio 1.29.9 / 1.30.6 / 1.31.2) or remove the Brotli decompressor filter until they are"
  done <<< "$PROXY_DECOMPRESSOR_HITS"
}

# ---------------------------------------------------- Node.js packages ---

# npm_lock_pkgs FILE: "name<TAB>version" for packages relevant to the CVE
npm_lock_pkgs() {
  local f=$1
  case $(basename "$f") in
    package-lock.json|npm-shrinkwrap.json)
      awk '
        /"([^"]*node_modules\/)?(express|body-parser|iltorb)": \{/ {
          n = $0; sub(/^[^"]*"/, "", n); sub(/".*/, "", n); sub(/.*node_modules\//, "", n); name = n }
        name != "" && /"version":/ { v = $0; sub(/.*"version": *"/, "", v); sub(/".*/, "", v); print name "\t" v; name = "" }
        /^[[:space:]]*\}/ { name = "" }' "$f" ;;
    yarn.lock)
      awk '
        /^[^[:space:]#]/ { name = ""; l = $0; gsub(/"/, "", l); if (l ~ /^(express|body-parser|iltorb)@/) { sub(/@.*/, "", l); name = l }; next }
        name != "" && /^[[:space:]]+version:? / { v = $0; sub(/^[[:space:]]+version:? *"?/, "", v); sub(/".*/, "", v); print name "\t" v; name = "" }' "$f" ;;
    pnpm-lock.yaml)
      awk '
        { l = $0; sub(/^[[:space:]]+/, "", l); sub(/^\047/, "", l); sub(/^\//, "", l) }
        l ~ /^(express|body-parser|iltorb)[@\/][0-9]/ { n = l; sub(/[@\/].*/, "", n); v = substr(l, length(n) + 2); sub(/[(:\047\/].*/, "", v); print n "\t" v }' "$f" ;;
    bun.lock)
      grep -Eo '"(express|body-parser|iltorb)@[0-9][^"]*"' "$f" | tr -d '"' | sed 's/@/	/' ;;
  esac
}

report_node_pkg() {
  local name=$1 v=$2 where=$3
  case $name in
    iltorb)
      report VULN "iltorb $v: unmaintained native binding that bundles an old, unpatched Brotli C decoder" "$where" \
        "remove iltorb and use Node's built-in zlib.brotliDecompress* on a patched Node.js runtime" ;;
    express)
      if ! ver_lt "$v" 5.0.0 && ver_lt "$v" 5.3.1 && seen_once "pkg:express:$v"; then
        report INFO "express $v decodes Content-Encoding: br request bodies (exposure path; the fix is the Node.js runtime)" "$where"
      fi ;;
    body-parser)
      if ! ver_lt "$v" 2.0.0 && ver_lt "$v" 2.3.1 && seen_once "pkg:body-parser:$v"; then
        report INFO "body-parser $v decodes Content-Encoding: br request bodies (exposure path; the fix is the Node.js runtime)" "$where"
      fi ;;
  esac
}

check_node_packages() {
  section "Node.js dependencies"
  local f name v found=0
  while IFS= read -r f; do
    found=1
    while IFS=$'\t' read -r name v; do
      [ -n "$v" ] && report_node_pkg "$name" "$v" "$(relpath "$f")"
    done < <(npm_lock_pkgs "$f" | sort -u)
  done < <(manifests_matching '^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$')
  while IFS= read -r f; do
    found=1
    name=$(basename "$(dirname "$f")")
    v=$(grep -Eo '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
    [ -n "$v" ] && report_node_pkg "$name" "$v" "$(relpath "$f")"
  done < <(find "$ROOT" -name .git -prune -o -type f \( -path '*/node_modules/iltorb/package.json' \
             -o -path '*/node_modules/express/package.json' -o -path '*/node_modules/body-parser/package.json' \) -print 2>/dev/null)
  [ "$found" = 1 ] || report INFO "no npm/yarn/pnpm/bun lockfiles or node_modules found" ""
}

# ---------------------------------------------------- Python packages ---

# Extracts "name<TAB>spec" for Brotli-family requirements from requirement-like
# text (requirements.txt, pyproject.toml, setup.cfg/py, Pipfile).
py_req_extract() {
  awk '
  {
    line = tolower($0); sub(/^[[:space:]]*#.*/, "", line); sub(/[[:space:]]#.*/, "", line)
    gsub(/\[[^]"\047]*\]/, "", line)   # drop extras such as httpx[brotli]
    while (match(line, /(^|[^a-z0-9_.-])(brotlicffi|brotlipy|brotli)([^a-z0-9_.-]|$)/)) {
      pre = substr(line, RSTART, RLENGTH); name = pre; gsub(/[^a-z]/, "", name)
      rest = substr(line, RSTART + index(pre, name) - 1 + length(name))
      spec = rest
      sub(/^[[:space:]]*\[[^]]*\]/, "", spec)
      sub(/^[[:space:]]*=[[:space:]]*\{?[[:space:]]*(version[[:space:]]*=[[:space:]]*)?["\047]/, "", spec)
      if (match(spec, /^[[:space:]]*(===|==|>=|<=|~=|!=|>|<|[~^])[[:space:]]*[0-9][0-9a-z.*]*([[:space:]]*,[[:space:]]*(===|==|>=|<=|~=|!=|>|<)[[:space:]]*[0-9][0-9a-z.*]*)*/))
        spec = substr(spec, RSTART, RLENGTH)
      else spec = ""
      gsub(/[[:space:]]/, "", spec)
      print name "\t" spec
      line = rest
    }
  }' "$1" | sort -u
}

# "name<TAB>version" of interesting packages in poetry.lock / uv.lock / pdm.lock
py_toml_lock_pkgs() {
  awk '
    /^\[\[package\]\]/ { name = "" }
    /^name = / { n = $3; gsub(/"/, "", n); name = tolower(n) }
    /^version = / && name != "" { v = $3; gsub(/"/, "", v); print name "\t" v; name = "" }' "$1"
}

py_pipfile_lock_pkgs() {
  awk '
    /^[[:space:]]*"[^"]+": \{/ { n = $0; sub(/^[[:space:]]*"/, "", n); sub(/".*/, "", n); name = tolower(n) }
    /"version": "==/ && name != "" { v = $0; sub(/.*"version": "==/, "", v); sub(/".*/, "", v); print name "\t" v; name = "" }' "$1"
}

# conda environment.yml / conda-lock.yml
py_conda_pkgs() {
  awk '
    /^[[:space:]]*-[[:space:]]*name:[[:space:]]*/ { n = $0; sub(/.*name:[[:space:]]*/, "", n); name = n; next }
    /^[[:space:]]*version:[[:space:]]*/ && name != "" { v = $0; sub(/.*version:[[:space:]]*/, "", v); gsub(/["\047]/, "", v); print name "\t==" v; name = ""; next }
    /^[[:space:]]*-[[:space:]]*(brotli|brotli-python|brotli-bin|libbrotlidec|libbrotlicommon|brotlicffi)([[:space:]]*[=<>!~].*)?[[:space:]]*$/ {
      s = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", s)
      n = s; sub(/[[:space:]]*[=<>!~].*/, "", n)
      v = substr(s, length(n) + 1); gsub(/[[:space:]]/, "", v)
      # conda "=1.1.0" / "=1.1.0=build" and pip "==1.1.0" -> "==1.1.0"
      if (v ~ /^==?[0-9]/) { sub(/^==?/, "", v); sub(/=.*/, "", v); v = "==" v }
      print n "\t" v
    }' "$1" | awk -F'\t' '$1 ~ /^(brotli|brotli-python|brotli-bin|libbrotlidec|libbrotlicommon|brotlicffi)$/'
}

py_fix_cmd() {
  case $1 in
    brotlicffi) echo "pip install -U \"brotlicffi>=$PY_BROTLICFFI_FIX\"" ;;
    brotlipy) echo "pip uninstall brotlipy && pip install \"brotlicffi>=$PY_BROTLICFFI_FIX\"" ;;
    *) echo "pip install -U \"Brotli>=$PY_BROTLI_FIX\"" ;;
  esac
}

py_fixed_ver() {
  case $1 in brotlicffi) echo "$PY_BROTLICFFI_FIX" ;; *) echo "$PY_BROTLI_FIX" ;; esac
}

# py_version_status NAME VERSION: ok | vuln | old | deprecated
py_version_status() {
  case $1 in
    brotlipy) echo deprecated ;;
    # affected: 1.0.3 - 1.2.0.x (Wiz)
    brotlicffi) if ver_lt "$2" 1.0.3; then echo old; elif ver_lt "$2" "$PY_BROTLICFFI_FIX"; then echo vuln; else echo ok; fi ;;
    *) brotli_c_status "$2" ;;
  esac
}

# eval_py_pkg NAME SPEC LOCATION LOCKFIX
# SPEC: "==X" (exact/locked), a constraint, or empty.
eval_py_pkg() {
  local name=$1 spec=$2 where=$3 lockfix=$4 pretty fixed v lower upper st pep
  pretty=$name; [ "$name" = brotli ] && pretty=Brotli
  fixed=$(py_fixed_ver "$name")
  case $name in brotli-python|brotli-bin|libbrotlidec|libbrotlicommon) fixed=$PY_BROTLI_FIX ;; esac
  [ -n "$lockfix" ] || lockfix=$(py_fix_cmd "$name")
  if [ "$name" = brotlipy ]; then
    report WARN "brotlipy is deprecated and bundles an old Brotli decoder" "$where" "$(py_fix_cmd brotlipy)"
    return
  fi
  # Compatible-release operators carry an implicit upper bound:
  # PEP 440 "~=1.1.0" -> <1.2, "~=1.1" -> <2; Poetry "~1.1.0" / "~1.1" -> <1.2, "~1" -> <2
  case $spec in
    '~='[0-9]*|'~'[0-9]*)
      v=$(clean_ver "$spec")
      case $spec in '~='*) pep=1 ;; *) pep=0 ;; esac
      spec=">=$v,<$(printf '%s' "$v" | awk -F. -v pep=$pep '{
        n = pep ? NF - 1 : (NF >= 2 ? 2 : 1); if (n < 1) n = 1
        for (i = 1; i <= n; i++) printf "%s%d", (i > 1 ? "." : ""), $i + (i == n) }')"
      ;;
  esac
  spec=$(printf '%s' "$spec" | sed -E 's/^\^/>=/; s/~=/>=/g')
  case $spec in
    ===*|==*)
      v=$(clean_ver "$spec")
      case $spec in *'*'*)
        report WARN "$pretty pinned to wildcard '$spec' may resolve to a vulnerable version" "$where" "$lockfix"; return ;;
      esac
      st=$(py_version_status "$name" "$v")
      case $st in
        vuln) PY_VULN_FOUND=1
              report VULN "$pretty $v bundles the vulnerable Brotli decoder (fixed in $fixed)" "$where" "$lockfix" ;;
        old) report WARN "$pretty $v predates the affected range but is years out of date" "$where" "$lockfix" ;;
        *) report OK "$pretty $v is patched" "$where" ;;
      esac
      return ;;
  esac
  lower=$(printf '%s' "$spec" | sed -nE 's/.*>=?([0-9][0-9.]*).*/\1/p')
  upper=$(printf '%s' "$spec" | sed -nE 's/.*<=?([0-9][0-9.]*).*/\1/p')
  if [ -n "$upper" ] && ! ver_lt "$fixed" "$upper" && ! { printf '%s' "$spec" | grep -q '<=' && [ "$(ver_cmp "$upper" "$fixed")" = 0 ]; }; then
    PY_VULN_FOUND=1
    report VULN "$pretty constraint '$spec' excludes the fixed release $fixed" "$where" "raise the constraint to \"$pretty>=$fixed\" in $where and re-lock"
  elif [ -z "$lower" ]; then
    report INFO "$pretty is required without a lower bound ('${spec:-any}'); the lockfile/installed version decides" "$where"
  elif ver_lt "$lower" "$fixed"; then
    report WARN "$pretty constraint '$spec' still allows vulnerable versions" "$where" "raise the constraint to \"$pretty>=$fixed\" in $where and regenerate the lockfile"
  else
    report OK "$pretty constraint '$spec' requires a patched version" "$where"
  fi
}

note_py_extras() {
  local f=$1 hit
  hit=$(grep -Eio '(httpx|urllib3)\[[^]]*brotli[^]]*\]|aiohttp\[[^]]*speedups[^]]*\]' "$f" 2>/dev/null | sort -u | tr '\n' ' ')
  [ -n "$hit" ] && report INFO "extras that pull in Brotli: $hit— remove them to stop reinstalling it if you uninstall Brotli as a stopgap" "$(relpath "$f")"
}

py_track_other() {
  local name=$1 v=$2 where=$3
  case $name in
    urllib3|requests|aiohttp|httpx|scrapy)
      case " $PY_CLIENTS " in *" $name "*) ;; *) PY_CLIENTS="$PY_CLIENTS $name" ;; esac ;;
    pyarrow)
      seen_once "pyarrow" && report WARN "pyarrow${v:+ $v}: Apache Arrow's bundled Brotli (1.0.9) is unpatched (arrow issue #55166)" "$where" \
        "do not read Brotli-compressed Parquet from untrusted sources until pyarrow ships Brotli >= 1.0.10; upgrade pyarrow when released" ;;
    duckdb)
      seen_once "duckdb" && report WARN "duckdb${v:+ $v} bundles an unpatched Brotli decoder (fix in progress, duckdb PR #27791)" "$where" \
        "do not read Brotli-compressed Parquet from untrusted sources until a fixed duckdb release; then upgrade" ;;
    pillow)
      seen_once "pillow" && report INFO "Pillow${v:+ $v} wheels bundle libbrotlidec (used for WOFF2 fonts); the binary scan verifies the installed copy" "$where" ;;
  esac
}

lock_fix_for() {
  local base=$1 name=$2 pretty=$2
  [ "$name" = brotli ] && pretty=Brotli
  case $base in
    poetry.lock) echo "poetry add \"$pretty>=$(py_fixed_ver "$name")\" (or 'poetry update $name' if transitive) and commit poetry.lock" ;;
    uv.lock) echo "uv lock --upgrade-package $name (and raise the constraint to >=$(py_fixed_ver "$name")), then uv sync" ;;
    pdm.lock) echo "pdm update $name (raise the constraint to >=$(py_fixed_ver "$name")) and commit pdm.lock" ;;
    Pipfile.lock) echo "pipenv update $name (raise the constraint to >=$(py_fixed_ver "$name")) and commit Pipfile.lock" ;;
    *) echo "pin $pretty==$(py_fixed_ver "$name") in $3 (pip-compile --upgrade-package $name if generated), then reinstall" ;;
  esac
}

check_python_manifests() {
  section "Python dependencies"
  local f rel base name spec v found=0
  while IFS= read -r f; do
    rel=$(relpath "$f"); base=$(basename "$f"); found=1
    case $base in
      poetry.lock|uv.lock|pdm.lock|Pipfile.lock)
        while IFS=$'\t' read -r name v; do
          case $name in
            brotli|brotlicffi|brotlipy) eval_py_pkg "$name" "==$v" "$rel" "$(lock_fix_for "$base" "$name" "$rel")" ;;
            *) py_track_other "$name" "$v" "$rel" ;;
          esac
        done < <(if [ "$base" = Pipfile.lock ]; then py_pipfile_lock_pkgs "$f"; else py_toml_lock_pkgs "$f"; fi | sort -u)
        ;;
      *.yml|*.yaml)
        case $base in environment*|*conda*) ;; *) continue ;; esac
        while IFS=$'\t' read -r name spec; do
          case $name in
            brotlicffi) eval_py_pkg brotlicffi "$spec" "$rel (conda)" "conda install \"brotlicffi>=$PY_BROTLICFFI_FIX\" and re-export $rel" ;;
            *) eval_py_pkg "$name" "$spec" "$rel (conda: $name)" "conda update brotli-python libbrotlidec libbrotlicommon (to >= $PY_BROTLI_FIX or a build with the fix) and re-export $rel" ;;
          esac
        done < <(py_conda_pkgs "$f")
        ;;
      *)
        while IFS=$'\t' read -r name spec; do
          case $base in
            *.txt|*.in) eval_py_pkg "$name" "$spec" "$rel" "$(lock_fix_for "$base" "$name" "$rel")" ;;
            *) eval_py_pkg "$name" "$spec" "$rel" ;;
          esac
        done < <(py_req_extract "$f")
        while IFS= read -r name; do
          py_track_other "$name" "" "$rel"
        done < <(tr 'A-Z' 'a-z' < "$f" | sed -E 's/^[[:space:]]*#.*//; s/[[:space:]]#.*//' | grep -Eo '(^|[^a-z0-9_.-])(pyarrow|duckdb|pillow|urllib3|requests|aiohttp|httpx|scrapy)([^a-z0-9_.-]|$)' |
                 sed -E 's/[^a-z0-9]//g' | sort -u)
        note_py_extras "$f"
        ;;
    esac
  done < <({ manifests_matching '(requirements.*\.(txt|in)|^constraints.*\.txt|^pyproject\.toml|^setup\.(cfg|py)|^Pipfile(\.lock)?|^(poetry|uv|pdm)\.lock|^environment.*\.ya?ml|conda.*\.ya?ml)$'
             awk '/\/requirements\/[^\/]*\.txt$/' "$WORK/manifests"; } | sort -u)
  [ "$found" = 1 ] || report INFO "no Python manifests or lockfiles found" ""

  # Packages installed in virtualenvs inside the repository
  while IFS= read -r f; do
    IFS=$'\t' read -r name v <<< "$(distinfo_pkg "$f")"
    [ -n "$v" ] || continue
    eval_py_pkg "$name" "==$v" "$(relpath "$f") (installed)" "$(py_fix_cmd "$name") inside that environment"
  done < <(find "$ROOT" -name .git -prune -o \( -iname 'brotli-*.dist-info' -o -iname 'brotlicffi-*.dist-info' \
             -o -iname 'brotlipy-*.dist-info' -o -iname 'brotli-*.egg-info' -o -iname 'brotlicffi-*.egg-info' \) -print 2>/dev/null)
}

# "name<TAB>version" from a .dist-info / .egg-info directory name
distinfo_pkg() {
  local base name v
  base=$(basename "$1")
  name=$(printf '%s' "$base" | sed -E 's/-[0-9].*//' | tr 'A-Z_' 'a-z-')
  v=$(printf '%s' "$base" | sed -nE 's/^[^-]+-([0-9][^-]*)(-py[0-9.]+)?\.(dist|egg)-info$/\1/p')
  [ -n "$v" ] && printf '%s\t%s\n' "$name" "$v"
}

python_exposure_note() {
  if [ "$PY_VULN_FOUND" = 1 ] && [ -n "$PY_CLIENTS" ]; then
    report INFO "HTTP clients found that decode Content-Encoding: br automatically when Brotli/brotlicffi is installed:$PY_CLIENTS" ""
  fi
}

# ------------------------------------------------ vendored C decoders ---

vendored_version() {
  local dir=$1 i vh maj min pat hex
  for i in 1 2 3 4 5; do
    dir=$(dirname "$dir")
    for vh in "$dir/common/version.h" "$dir/c/common/version.h"; do
      [ -f "$vh" ] || continue
      maj=$(sed -nE 's/^#define BROTLI_VERSION_MAJOR ([0-9]+).*/\1/p' "$vh")
      min=$(sed -nE 's/^#define BROTLI_VERSION_MINOR ([0-9]+).*/\1/p' "$vh")
      pat=$(sed -nE 's/^#define BROTLI_VERSION_PATCH ([0-9]+).*/\1/p' "$vh")
      if [ -n "$maj" ]; then echo "$maj.$min.$pat"; return; fi
      hex=$(sed -nE 's/^#define BROTLI_VERSION 0x([0-9A-Fa-f]+).*/\1/p' "$vh")
      if [ -n "$hex" ]; then hex=$((16#$hex)); echo "$((hex >> 24)).$(((hex >> 12) & 4095)).$((hex & 4095))"; return; fi
    done
  done
}

check_vendored_sources() {
  section "Vendored Brotli C sources"
  local f rel ver found=0 line
  while IFS= read -r f; do
    grep -q -F 'EXUBERANT_NIBBLE' "$f" 2>/dev/null || continue
    found=1; rel=$(relpath "$f"); ver=$(vendored_version "$f")
    if grep -q -F 'BLOCK_SWITCH' "$f"; then
      report OK "vendored Brotli decoder${ver:+ $ver} includes the BLOCK_SWITCH fix" "$rel"
    else
      report VULN "vendored Brotli decoder${ver:+ $ver} lacks the BLOCK_SWITCH fix" "$rel" \
        "update the vendored copy to Brotli $UPSTREAM_FIXES or cherry-pick google/brotli 0ed4268 (+50a9b70, b418fa8, da98063), then rebuild"
    fi
  done < <(find "$ROOT" -name .git -prune -o -type f -name decode.h -print 2>/dev/null)

  # Submodules and build-system references to google/brotli
  local lineno text
  while IFS= read -r f; do
    rel=$(relpath "$f")
    # each reference plus the two following lines (FetchContent GIT_TAG etc.)
    while IFS=$'\t' read -r lineno text; do
      found=1
      ver=$(printf '%s' "$text" | grep -Eio '(git_tag|tag|version|brotli[/@-]|refs/tags/)[[:space:]=:"'\'']*v?1\.[0-9]+\.[0-9]+' |
            head -1 | grep -Eo '1\.[0-9]+\.[0-9]+')
      if [ -n "$ver" ] && [ "$(brotli_c_status "$ver")" = vuln ]; then
        report VULN "build fetches Brotli $ver" "$rel:$lineno" "bump it to Brotli $UPSTREAM_FIXES (e.g. v1.2.1) and rebuild"
      elif [ -n "$ver" ]; then
        report OK "build fetches Brotli $ver" "$rel:$lineno"
      else
        report INFO "build references Brotli; verify the pinned revision includes commit 0ed4268" "$rel:$lineno"
      fi
    done < <(awk '{ L[NR] = $0 }
      END {
        for (i = 1; i <= NR; i++) if (tolower(L[i]) ~ /google\/brotli|brotli\/[0-9]|"brotli"|brotli[[:space:]]*(git_tag|url)/) {
          b = L[i]; for (j = i + 1; j <= i + 2 && j <= NR; j++) b = b " " L[j]
          gsub(/\t/, " ", b); print i "\t" b
        }
      }' "$f")
  done < <(manifests_matching '^(\.gitmodules|CMakeLists\.txt|.*\.cmake|meson\.build|conanfile\.(txt|py)|vcpkg\.json|MODULE\.bazel|WORKSPACE|.*\.bzl)$')
  [ "$found" = 1 ] || report INFO "no vendored Brotli sources or build references found" ""
}

# ------------------------------------------------- other ecosystems ---

check_other_ecosystems() {
  section "Other ecosystems"
  local f rel v found=0
  while IFS= read -r f; do
    rel=$(relpath "$f")
    case $(basename "$f") in
      Gemfile.lock)
        v=$(sed -nE 's/^[[:space:]]+brotli \(([0-9.]+)(-[^)]*)?\)$/\1/p' "$f" | head -1)
        [ -n "$v" ] || continue
        found=1
        if ver_lt "$v" "$RUBY_BROTLI_FIX"; then
          report VULN "Ruby brotli gem $v bundles a vulnerable decoder (fixed in $RUBY_BROTLI_FIX)" "$rel" "bundle update brotli (to >= $RUBY_BROTLI_FIX) and commit Gemfile.lock"
        else
          report OK "Ruby brotli gem $v is patched" "$rel"
        fi ;;
      go.mod)
        if grep -q 'andybalholm/brotli' "$f"; then
          found=1; v=$(sed -nE 's/.*andybalholm\/brotli[[:space:]]+(v[^[:space:]]+).*/\1/p' "$f" | head -1)
          if [ -z "$v" ]; then
            report INFO "Go port andybalholm/brotli referenced without a version (fixed in $GO_BROTLI_FIX)" "$rel"
          elif ver_lt "$(clean_ver "$v")" "${GO_BROTLI_FIX#v}"; then
            report VULN "Go port andybalholm/brotli $v is affected (fixed in $GO_BROTLI_FIX)" "$rel" \
              "go get github.com/andybalholm/brotli@$GO_BROTLI_FIX && go mod tidy, then rebuild"
          else
            report OK "Go port andybalholm/brotli $v is patched" "$rel"
          fi
        fi
        if grep -q 'google/brotli/go/cbrotli' "$f"; then
          found=1
          report WARN "cgo binding google/brotli/go/cbrotli links the C library" "$rel" \
            "upgrade the system/static libbrotli the binary links against to $UPSTREAM_FIXES and rebuild"
        fi ;;
      Cargo.lock)
        if grep -qE '^name = "brotli-sys"|^name = "brotlic-sys"' "$f"; then
          found=1
          report WARN "Rust crate wrapping the Brotli C library found (brotli-sys/brotlic-sys)" "$rel" \
            "update it to a release bundling Brotli $UPSTREAM_FIXES, or switch to the pure-Rust 'brotli' crate"
        elif grep -q '^name = "brotli-decompressor"' "$f"; then
          found=1
          report OK "Rust brotli-decompressor catches the condition (not affected)" "$rel"
        fi ;;
      *.csproj|*.fsproj|*.vbproj)
        seen_once dotnet || continue
        found=1
        if grep -rqE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=bin --exclude-dir=obj \
             --include='*.cs' --include='*.fs' --include='*.vb' \
             'BrotliStream|BrotliDecoder|DecompressionMethods\.(Brotli|All)|AddRequestDecompression' "$ROOT" 2>/dev/null; then
          report WARN ".NET project uses Brotli decoding; .NET runtimes before $DOTNET_FIXES bundle a vulnerable decoder" "$rel" \
            "run .NET runtime $DOTNET_FIXES or later (update the SDK / runtime images, e.g. mcr.microsoft.com/dotnet/aspnet:8.0.33, and redeploy); runtimes built from public GitHub source are still affected"
        else
          report INFO ".NET project found (no direct Brotli use detected); .NET runtimes before $DOTNET_FIXES bundle a vulnerable decoder" "$rel"
        fi ;;
      pom.xml|build.gradle|build.gradle.kts)
        if grep -q 'brotli4j' "$f"; then
          found=1
          report INFO "Brotli4j (JNI) is fixed upstream; make sure you use its latest release" "$rel"
        fi ;;
      composer.json)
        if grep -q '"ext-brotli"' "$f"; then
          found=1
          report WARN "requires the PHP brotli extension (fixed in $PHP_BROTLI_FIX)" "$rel" "pecl upgrade brotli (>= $PHP_BROTLI_FIX) on every PHP host and restart PHP-FPM"
        fi ;;
    esac
  done < <(manifests_matching '^(Gemfile\.lock|go\.mod|Cargo\.lock|.*\.(cs|fs|vb)proj|pom\.xml|build\.gradle(\.kts)?|composer\.json)$')
  [ "$found" = 1 ] || report INFO "nothing relevant found (Ruby, Go, Rust, .NET, Java, PHP)" ""
}

# ---------------------------------------------- direct decoder usage ---

# print_hits "file:line:text" lines (grep -rn output) under the previous finding, at most 15
print_hits() {
  local count
  count=$(printf '%s\n' "$1" | wc -l | tr -d ' ')
  printf '%s\n' "$1" | head -15 | while IFS= read -r line; do
    printf '         %s%s%s\n' "$C_DIM" "$(relpath "${line%%:*}"):$(printf '%s' "$line" | cut -d: -f2)" "$C_RESET"
  done
  [ "$count" -gt 15 ] && printf '         %s... and %s more%s\n' "$C_DIM" "$((count - 15))" "$C_RESET"
}

check_call_sites() {
  section "Direct Brotli decoding in source (decoder calls, curl --compressed)"
  local hits count
  hits=$(grep -rnE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv \
           --exclude-dir=.tox --exclude-dir=.nox --exclude-dir=site-packages --exclude-dir=dist --exclude-dir=build \
           --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.jsx' --include='*.ts' --include='*.mts' \
           --include='*.tsx' --include='*.py' \
           'brotliDecompress|createBrotliDecompress|BrotliDecompress|brotli(cffi)?\.(decompress|Decompressor)|^[[:space:]]*(import|from)[[:space:]]+brotli(cffi)?([[:space:].,]|$)' \
           "$ROOT" 2>/dev/null)
  if [ -z "$hits" ]; then
    report INFO "no direct calls found (HTTP clients and body parsers may still decode br implicitly)" ""
  else
    count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    report INFO "$count call site(s) decode Brotli directly; prioritize them if they handle untrusted data" ""
    print_hits "$hits"
  fi

  # curl only decodes responses when asked to (--compressed / CURLOPT_ACCEPT_ENCODING)
  hits=$( { grep -rnE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv \
              --exclude-dir=.tox --exclude-dir=site-packages \
              --include='*.sh' --include='*.bash' --include='*.zsh' --include='*.yml' --include='*.yaml' \
              --include='Dockerfile*' --include='Makefile' --include='*.mk' --include='*.c' --include='*.cc' \
              --include='*.cpp' --include='*.h' --include='*.php' --include='*.py' --include='*.rb' \
              -e 'curl[^|;&]*[[:space:]]--compressed' -e 'CURLOPT_ACCEPT_ENCODING' "$ROOT" 2>/dev/null
            find "$ROOT" -name .git -prune -o -type f -name .curlrc -print 2>/dev/null |
              while IFS= read -r f; do grep -nHE '^[[:space:]]*(--)?compressed' "$f"; done; } )
  if [ -n "$hits" ]; then
    count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    report INFO "$count place(s) make curl/libcurl decode compressed responses; with a Brotli-enabled curl this reaches the decoder, so make sure that curl/libbrotlidec is patched" ""
    print_hits "$hits"
  fi
}

# -------------------------------------------------- native binaries ---

check_repo_binaries() {
  section "Native binaries in the repository (node_modules, virtualenvs, vendored libs)"
  local f found=0
  while IFS= read -r f; do
    found=1
    check_binary "$f" "native binary"
  done < <(find "$ROOT" -name .git -prune -o -type f \( -name '*.node' -o -name '*.so' -o -name '*.so.*' \
             -o -name '*.dylib' -o -name '*.pyd' -o -name '*.dll' -o -name '*.jnilib' -o -name '*.a' \) \
             -size -300M -print0 2>/dev/null | xargs -0 grep -a -l -F "$DECODER_MARKER" 2>/dev/null)
  [ "$found" = 1 ] || report INFO "no native binaries embedding a Brotli decoder found" ""
}

# ------------------------------------------------------- this machine ---

check_node_runtime() {
  section "Node.js on this machine"
  local node v bv shared real st target
  node=$(command -v node 2>/dev/null)
  if [ -z "$node" ]; then
    report INFO "node not found in PATH" ""
  else
    # NODE_OPTIONS could preload modules (--require); run node without it
    v=$(env -u NODE_OPTIONS node --version 2>/dev/null); real=$(resolve_path "$node")
    bv=$(env -u NODE_OPTIONS node -p 'process.versions.brotli' 2>/dev/null)
    shared=$(env -u NODE_OPTIONS node -p 'process.config.variables.node_shared_brotli' 2>/dev/null)
    st=$(node_status "$v"); target=$(product_target node "$(clean_ver "$v" | cut -d. -f1)")
    if [ "$shared" = true ]; then
      report INFO "node $v links the system libbrotli (distro build); it is patched by the system library update below" "$real"
    elif [ "$st" = ok ]; then
      report OK "node $v (bundled Brotli $bv) is patched" "$real"
    elif [ "$(binary_decoder_state "$real")" = patched ]; then
      report WARN "node $v is older than the fixed release but its decoder contains the fix (vendor backport?)" "$real" \
        "confirm with your Node.js vendor, or upgrade to $target"
    elif [ "$st" = eol ]; then
      report VULN "node $v (bundled Brotli $bv) is end-of-life; no patched release" "$real" \
        "install Node.js $NODE_DEFAULT_TARGET (e.g. nvm install $NODE_DEFAULT_TARGET && nvm alias default $NODE_DEFAULT_TARGET) and restart Node processes"
    else
      report VULN "node $v (bundled Brotli $bv) is vulnerable (fixed in $target)" "$real" \
        "install Node.js $target (e.g. nvm install $target && nvm alias default $target) and restart Node processes"
    fi
  fi

  # Other installs managed by version managers
  local mgr dir d name vulns oks
  for mgr in \
      "nvm|${NVM_DIR:-$HOME/.nvm}/versions/node" \
      "fnm|${FNM_DIR:-$HOME/.local/share/fnm}/node-versions" \
      "fnm|$HOME/Library/Application Support/fnm/node-versions" \
      "volta|${VOLTA_HOME:-$HOME/.volta}/tools/image/node" \
      "asdf|${ASDF_DATA_DIR:-$HOME/.asdf}/installs/nodejs" \
      "mise|${MISE_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/mise}/installs/node" \
      "n|${N_PREFIX:-/usr/local}/n/versions/node"; do
    name=${mgr%%|*}; dir=${mgr#*|}
    [ -d "$dir" ] || continue
    vulns=""; oks=""
    for d in "$dir"/*; do
      [ -d "$d" ] && [ ! -L "$d" ] || continue
      v=$(clean_ver "$(basename "$d")")
      case $v in *.*.*) ;; *) continue ;; esac
      if [ "$(node_status "$v")" = ok ]; then oks="$oks $v"; else vulns="$vulns $v"; fi
    done
    if [ -n "$vulns" ]; then
      report VULN "$name has vulnerable Node.js installs:$vulns" "$dir" \
        "$name: install $NODE_DEFAULT_TARGET (or 22.23.4 / 26.12.1), make it the default, and uninstall the vulnerable versions:$vulns"
    fi
    [ -n "$oks" ] && report OK "$name has patched Node.js installs:$oks" "$dir"
  done

  if command -v brew >/dev/null 2>&1; then
    while read -r name v; do
      v=${v%%_*}
      if [ "$(node_status "$v")" = ok ]; then
        report OK "Homebrew $name $v is patched" ""
      else
        report VULN "Homebrew $name $v is vulnerable" "" "brew upgrade $name (or move to a patched node formula)"
      fi
    done < <(brew list --versions 2>/dev/null | awk '$1 ~ /^node(@[0-9]+)?$/ { print $1, $NF }')
  fi
}

check_bun_envoy_curl() {
  section "Bun, Envoy and curl on this machine"
  local bin v any=0
  for bin in $(command -v bun 2>/dev/null) "${BUN_INSTALL:-$HOME/.bun}/bin/bun"; do
    [ -x "$bin" ] || continue
    seen_once "bun:$(resolve_path "$bin")" || continue
    v=$("$bin" --version 2>/dev/null)
    [ -n "$v" ] || continue
    any=1
    case $(product_status bun "$v") in
      vuln) report VULN "Bun $v bundles a vulnerable Brotli decoder (fixed in $(product_target bun ""))" "$bin" \
              "bun upgrade (to >= $(product_target bun "")), rebuild executables made with 'bun build --compile' and restart Bun processes" ;;
      old) report OK "Bun $v predates the affected releases (1.0.21 - 1.4.3)" "$bin" ;;
      *) report OK "Bun $v is patched" "$bin" ;;
    esac
  done

  if command -v envoy >/dev/null 2>&1; then
    # "envoy  version: <sha>/1.38.5/Clean/RELEASE/BoringSSL"
    v=$(envoy --version 2>/dev/null | grep -Eo '/[0-9]+\.[0-9]+\.[0-9]+/' | head -1 | tr -d /)
    if [ -n "$v" ]; then
      any=1
      eval_runtime_spec envoy "$v" "$(command -v envoy)" "upgrade Envoy to @V@ (or newer on a supported branch) and restart it" \
        WARN " (only reachable if a Brotli decompressor filter is configured)"
    fi
  fi

  # curl decodes Brotli only with --compressed and only when built with Brotli support
  for bin in $(command -v curl 2>/dev/null) /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl; do
    [ -x "$bin" ] || continue
    seen_once "curl:$(resolve_path "$bin")" || continue
    any=1
    v=$("$bin" -V 2>/dev/null | awk 'NR == 1 { print $2 }')
    if ! "$bin" -V 2>/dev/null | grep -i '^Features:' | grep -qiw brotli; then
      report OK "curl $v is built without Brotli support" "$bin"
      continue
    fi
    case $(binary_decoder_state "$(resolve_path "$bin")") in
      vulnerable) report VULN "curl $v has an unpatched Brotli decoder linked in statically" "$bin" \
                    "upgrade curl to a build with Brotli $UPSTREAM_FIXES (your vendor's update, or brew upgrade curl)" ;;
      patched) report OK "curl $v has a patched Brotli decoder linked in statically" "$bin" ;;
      *) report INFO "curl $v decodes Brotli (with --compressed) through the shared libbrotlidec; see the system library check" "$bin" ;;
    esac
  done
  [ "$any" = 1 ] || report INFO "Bun, Envoy and curl not found" ""
}

# Runs with -I, which also hides the user site directory (pip install --user),
# so that directory is read explicitly and its packages are tagged with it.
PY_PROBE='
import os, sys, site
want = {"brotli", "brotlicffi", "brotlipy", "urllib3", "requests", "aiohttp", "httpx", "scrapy", "pyarrow", "duckdb", "pillow"}
try:
    user = site.getusersitepackages()
except Exception:
    user = ""
print("PREFIX\t" + sys.prefix)
try:
    import importlib.metadata as m
    found = set()
    for where, kw in (("", {}), (user, {"path": [user]})):
        if kw and not os.path.isdir(user):
            continue
        for d in m.distributions(**kw):
            n = (d.metadata.get("Name") or "").lower()
            if n in want:
                found.add((n, d.version, where))
    for n, v, where in sorted(found):
        print("PKG\t%s\t%s\t%s" % (n, v, where))
except Exception:
    pass
try:
    paths = site.getsitepackages() + [user]
except Exception:
    paths = [user]
for p in paths:
    if p:
        print("SITE\t" + p)
'

check_python_interpreters() {
  section "Python on this machine"
  local py prefixes=$'\n' out prefix kind a b c where sites f any=0
  for py in $(command -v python3 python 2>/dev/null) \
            "${PYENV_ROOT:-$HOME/.pyenv}"/versions/*/bin/python3 \
            "$HOME"/miniconda3/bin/python3 "$HOME"/anaconda3/bin/python3 "$HOME"/miniforge3/bin/python3; do
    [ -x "$py" ] || continue
    out=$("$py" -I -c "$PY_PROBE" 2>/dev/null) || continue
    prefix=$(printf '%s\n' "$out" | awk -F'\t' '$1 == "PREFIX" { print $2 }')
    case $prefixes in *$'\n'"$prefix"$'\n'*) continue ;; esac
    prefixes="$prefixes$prefix"$'\n'; any=1
    printf '  %s%s%s\n' "$C_DIM" "$prefix" "$C_RESET"
    local hit=0
    while IFS=$'\t' read -r kind a b c; do
      [ "$kind" = PKG ] || continue
      where=$prefix
      if [ -n "$c" ]; then
        # user site directories are shared by interpreters of the same Python version
        seen_once "pyuser:$c:$a:$b" || continue
        where="$c (user site)"
      fi
      case $a in
        brotli|brotlicffi|brotlipy)
          hit=1; eval_py_pkg "$a" "==$b" "$where" "$py -m $(py_fix_cmd "$a")${c:+ --user}" ;;
        *) py_track_other "$a" "$b" "$where" ;;
      esac
    done <<< "$out"
    [ "$hit" = 1 ] || report OK "Brotli / brotlicffi packages not installed" ""
    # Brotli decoders shipped inside wheels (Brotli, brotlicffi, Pillow, pyarrow, ...)
    if [ "$SCAN_BINARIES" = 1 ]; then
      while IFS= read -r sites; do
        [ -d "$sites" ] || continue
        while IFS= read -r f; do
          check_binary "$f" "wheel binary" "$py -m pip install -U @PKG@"
        done < <(native_decoder_files "$sites")
      done < <(printf '%s\n' "$out" | awk -F'\t' '$1 == "SITE" { print $2 }' | sort -u)
    fi
  done
  [ "$any" = 1 ] || report INFO "no Python interpreter found" ""
  check_external_venvs
  python_exposure_note
}

# Virtualenvs kept outside any repository by Poetry, pipx, uv, pipenv and
# virtualenvwrapper. Read from disk only; no interpreter is started.
check_external_venvs() {
  local entry mgr root env envname f name v spec tmpl count hits
  for entry in \
      "Poetry|${POETRY_VIRTUALENVS_PATH:-}" \
      "Poetry|$HOME/Library/Caches/pypoetry/virtualenvs" \
      "Poetry|${XDG_CACHE_HOME:-$HOME/.cache}/pypoetry/virtualenvs" \
      "pipx|${PIPX_HOME:+$PIPX_HOME/venvs}" \
      "pipx|$HOME/.local/pipx/venvs" \
      "pipx|${XDG_DATA_HOME:-$HOME/.local/share}/pipx/venvs" \
      "pipx|$HOME/Library/Application Support/pipx/venvs" \
      "uv tool|${UV_TOOL_DIR:-}" \
      "uv tool|${XDG_DATA_HOME:-$HOME/.local/share}/uv/tools" \
      "virtualenvwrapper|${WORKON_HOME:-$HOME/.virtualenvs}" \
      "pipenv|${XDG_DATA_HOME:-$HOME/.local/share}/virtualenvs"; do
    mgr=${entry%%|*}; root=${entry#*|}
    [ -n "$root" ] && [ -d "$root" ] || continue
    seen_once "venvroot:$(resolve_path "$root")" || continue
    set -- "$root"/*/
    [ -d "$1" ] || continue
    printf '  %s%s environments in %s%s\n' "$C_DIM" "$mgr" "$root" "$C_RESET"
    count=0; hits=0
    for env in "$root"/*/; do
      env=${env%/}
      [ -d "$env" ] || continue
      count=$((count + 1)); envname=$(basename "$env")
      # upgrade command for this environment; @PKG@ = package (or requirement)
      case $mgr in
        Poetry) tmpl="poetry update @PKG@ in the project that owns env '$envname' (or remove the env if stale)" ;;
        pipx) tmpl="pipx runpip $envname install -U @PKG@" ;;
        "uv tool") tmpl="uv tool install --force --with @PKG@ $envname" ;;
        virtualenvwrapper) tmpl="workon $envname && pip install -U @PKG@" ;;
        pipenv) tmpl="pipenv update @PKG@ in the project that owns env '$envname' (or remove the env if stale)" ;;
      esac
      while IFS= read -r f; do
        IFS=$'\t' read -r name v <<< "$(distinfo_pkg "$f")"
        [ -n "$v" ] || continue
        case $name in
          brotli|brotlicffi|brotlipy)
            hits=1
            case $mgr in
              Poetry|pipenv) spec="$name (with a >= $(py_fixed_ver "$name") constraint)" ;;
              *) spec="\"Brotli>=$PY_BROTLI_FIX\""; [ "$name" = brotlicffi ] && spec="\"brotlicffi>=$PY_BROTLICFFI_FIX\"" ;;
            esac
            eval_py_pkg "$name" "==$v" "$env ($mgr)" "${tmpl//@PKG@/$spec}" ;;
          *) py_track_other "$name" "$v" "$env ($mgr)" ;;
        esac
      done < <(find "$env" -maxdepth 6 -type d -path '*-packages/*' \( -iname 'brotli-[0-9]*' -o -iname 'brotlicffi-[0-9]*' \
                 -o -iname 'brotlipy-[0-9]*' -o -iname 'urllib3-[0-9]*' -o -iname 'requests-[0-9]*' -o -iname 'aiohttp-[0-9]*' \
                 -o -iname 'httpx-[0-9]*' -o -iname 'scrapy-[0-9]*' -o -iname 'pyarrow-[0-9]*' -o -iname 'duckdb-[0-9]*' \
                 -o -iname 'pillow-[0-9]*' \) 2>/dev/null)
      if [ "$SCAN_BINARIES" = 1 ]; then
        while IFS= read -r f; do
          hits=1
          check_binary "$f" "$mgr env '$envname' binary" "$tmpl"
        done < <(native_decoder_files "$env")
      fi
    done
    [ "$hits" = 1 ] || report OK "$count $mgr environment(s), no Brotli decoder found" ""
  done
}

check_system_brotli() {
  section "System Brotli library"
  local pkg v up doc found=0 f
  if command -v dpkg-query >/dev/null 2>&1; then
    while read -r pkg v; do
      found=1; up=$(printf '%s' "$v" | sed -E 's/^[0-9]+://; s/-[^-]*$//; s/[+~].*//')
      doc="/usr/share/doc/${pkg%%:*}/changelog.Debian.gz"
      if [ -f "$doc" ] && zgrep -q "$CVE" "$doc" 2>/dev/null; then
        report OK "$pkg $v (changelog lists the $CVE fix)" ""
      elif [ "$(brotli_c_status "$up")" != vuln ]; then
        report OK "$pkg $v" ""
      elif [ -f "$doc" ]; then
        report VULN "$pkg $v has no $CVE fix in its changelog" "" "sudo apt-get update && sudo apt-get install --only-upgrade ${pkg%%:*}, then restart services that use it"
      else
        report WARN "$pkg $v is in the affected range; could not confirm a backported fix" "" "sudo apt-get update && sudo apt-get install --only-upgrade ${pkg%%:*}"
      fi
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' '*brotli*' 2>/dev/null | awk '$1 ~ /^ii/ { print $2, $3 }')
  fi
  if command -v rpm >/dev/null 2>&1; then
    while read -r pkg v; do
      found=1; up=${v%%-*}
      if rpm -q --changelog "$pkg" 2>/dev/null | grep -q "$CVE"; then
        report OK "$pkg $v (changelog lists the $CVE fix)" ""
      elif [ "$(brotli_c_status "$up")" != vuln ]; then
        report OK "$pkg $v" ""
      else
        report VULN "$pkg $v has no $CVE fix in its changelog" "" "sudo dnf upgrade $pkg (or yum), then restart services that use it"
      fi
    done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' '*brotli*' 2>/dev/null)
  fi
  if command -v apk >/dev/null 2>&1; then
    while read -r pkg v; do
      found=1
      if [ "$(brotli_c_status "$(clean_ver "$v")")" = vuln ]; then
        report WARN "$pkg $v is in the affected range (check the library scan below for a backport)" "" "apk upgrade $pkg, then restart services that use it"
      else
        report OK "$pkg $v" ""
      fi
    done < <(apk info -v 2>/dev/null | grep -i brotli | sed -E 's/^(.*)-([0-9][^-]*-r[0-9]+)$/\1 \2/')
  fi
  if command -v brew >/dev/null 2>&1; then
    v=$(brew list --versions brotli 2>/dev/null | awk '{ print $NF }')
    if [ -n "$v" ]; then
      found=1
      if [ "$(brotli_c_status "$(clean_ver "$v")")" = vuln ]; then
        report VULN "Homebrew brotli $v is vulnerable" "" "brew upgrade brotli, then restart programs that link it"
      else
        report OK "Homebrew brotli $v" ""
      fi
    fi
  fi
  if command -v port >/dev/null 2>&1; then
    v=$(port -q installed brotli 2>/dev/null | awk '/active/ { print $2 }' | tr -d @)
    if [ -n "$v" ]; then
      found=1
      if [ "$(brotli_c_status "$(clean_ver "$v")")" = vuln ]; then
        report VULN "MacPorts brotli $v is vulnerable" "" "sudo port selfupdate && sudo port upgrade brotli"
      else
        report OK "MacPorts brotli $v" ""
      fi
    fi
  fi

  # The libraries themselves: decisive regardless of how they were packaged
  if [ "$SCAN_BINARIES" = 1 ]; then
    while IFS= read -r f; do
      found=1
      check_binary "$f" "system library"
    done < <(find /usr/lib /usr/lib64 /lib /lib64 /usr/local/lib /usr/local/Cellar/brotli /opt/homebrew/lib \
               /opt/homebrew/Cellar/brotli /opt/local/lib \
               -maxdepth 4 -type f -name 'libbrotlidec*' 2>/dev/null | sort -u)
  fi
  [ "$found" = 1 ] || report INFO "no system Brotli library found" ""

  # Linux: processes that have the decoder loaded
  if [ -r /proc/self/maps ]; then
    local pid comm stale="" users=""
    for f in /proc/[0-9]*/maps; do
      grep -q brotlidec "$f" 2>/dev/null || continue
      pid=${f#/proc/}; pid=${pid%/maps}; comm=$(cat "/proc/$pid/comm" 2>/dev/null)
      users="$users $comm($pid)"
      grep -q 'brotlidec.*(deleted)' "$f" 2>/dev/null && stale="$stale $comm($pid)"
    done
    [ -n "$users" ] && report INFO "processes with libbrotlidec loaded (run as root to see all):$users" ""
    [ -n "$stale" ] && report WARN "processes still using a replaced (old) libbrotlidec:$stale" "" "restart these processes so they load the patched library"
  fi
}

check_other_runtimes() {
  local v
  if command -v php >/dev/null 2>&1; then
    v=$(php -r 'echo phpversion("brotli");' 2>/dev/null)
    if [ -n "$v" ]; then
      seen_once other-runtimes && section "PHP / Ruby on this machine"
      if ver_lt "$v" "$PHP_BROTLI_FIX"; then
        report VULN "PHP brotli extension $v is vulnerable (fixed in $PHP_BROTLI_FIX)" "$(command -v php)" "pecl upgrade brotli (>= $PHP_BROTLI_FIX) and restart PHP-FPM / the web server"
      else
        report OK "PHP brotli extension $v is patched" "$(command -v php)"
      fi
    fi
  fi
  if command -v gem >/dev/null 2>&1; then
    v=$(gem list '^brotli$' 2>/dev/null | sed -nE 's/^brotli \(([^)]*)\).*/\1/p' | tr ',' '\n' | sed -E 's/^ *//; s/^default: //' | sort -t. -k1,1n -k2,2n -k3,3n | head -1)
    if [ -n "$v" ]; then
      seen_once other-runtimes && section "PHP / Ruby on this machine"
      if ver_lt "$v" "$RUBY_BROTLI_FIX"; then
        report VULN "Ruby brotli gem $v installed (fixed in $RUBY_BROTLI_FIX)" "$(command -v gem)" "gem update brotli && gem cleanup brotli"
      else
        report OK "Ruby brotli gem $v" "$(command -v gem)"
      fi
    fi
  fi
}

# ---------------------------------------------------------------- main ---

printf '%sBroccoli2Shell detector%s — %s (Brotli decoder out-of-bounds write → RCE)\n' "$C_BOLD" "$C_RESET" "$CVE"
printf 'Target: %s' "$ROOT"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf ' (git: %s)\n' "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null) @ $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo 'no commits yet')"
else
  printf ' (not a git repository; scanning the directory anyway)\n'
fi

check_version_pins
check_node_packages
check_python_manifests
[ "$SCAN_SYSTEM" = 1 ] || python_exposure_note
check_vendored_sources
check_other_ecosystems
check_call_sites
[ "$SCAN_BINARIES" = 1 ] && check_repo_binaries
if [ "$SCAN_SYSTEM" = 1 ]; then
  # Probe the machine from a neutral directory: php reads php.ini from the
  # current directory, and version-manager shims (asdf, volta, pyenv) would
  # otherwise pick the runtime pinned by the scanned repository.
  cd / || exit 2
  check_node_runtime
  check_bun_envoy_curl
  check_python_interpreters
  check_system_brotli
  check_other_runtimes
fi

section "Summary"
if [ "$VULN_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
  printf '  %sNo vulnerable Brotli decoders found.%s\n' "$C_GREEN" "$C_RESET"
else
  printf '  %s%d vulnerable%s, %s%d warning(s)%s\n' "$C_RED" "$VULN_COUNT" "$C_RESET" "$C_YELLOW" "$WARN_COUNT" "$C_RESET"
  printf '\n%sSuggested fixes%s\n' "$C_BOLD" "$C_RESET"
  awk '!seen[$0]++' "$FIX_FILE" | awk '{ printf "  %d. %s\n", NR, $0 }'
  cat <<EOF

${C_BOLD}After upgrading${C_RESET}
  - Restart every process, rebuild every image (docker build --pull) and redeploy,
    then verify that the patched components are the ones actually loaded.
  - Commit updated lockfiles, or the next build reinstalls the vulnerable version.
  - Rebuild executables that bundle a runtime (bun build --compile, statically
    linked curl or Brotli).
  - Check everywhere code runs: production, staging, CI runners, build images,
    serverless runtimes and laptops (docker run --rm --entrypoint node <image> --version).

${C_BOLD}If you cannot upgrade yet${C_RESET}
  - Python: pip uninstall Brotli brotlicffi (urllib3/requests/aiohttp fall back to
    gzip/deflate) and drop extras such as httpx[brotli] and aiohttp[speedups].
  - Inbound: reject request bodies with Content-Encoding: br at your proxy/WAF, e.g. nginx:
      if (\$http_content_encoding ~* "br") { return 415; }
  - Outbound: disable Brotli decompression in HTTP clients or reject responses with
    Content-Encoding: br before they are decoded. Removing br from Accept-Encoding
    alone does not help; a malicious server can send Brotli anyway.
  - Envoy / Istio: remove the Brotli decompressor filter until the proxies are patched.
  - curl: drop --compressed (scripts, aliases, CI, .curlrc) for untrusted URLs.
  - Node.js has no workaround: upgrading the runtime is the only complete fix.
  - Monitor WAF, application and network logs for Brotli-encoded traffic and watch
    for unexpected crashes of the affected services.

References: https://broccoli2shell.com
            https://www.wiz.io/blog/cve-2026-111497-brotli-rce-node-js
EOF
fi

if [ "$VULN_COUNT" -gt 0 ] || { [ "$STRICT" = 1 ] && [ "$WARN_COUNT" -gt 0 ]; }; then
  exit 1
fi
exit 0
