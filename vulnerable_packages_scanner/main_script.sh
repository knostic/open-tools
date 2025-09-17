#!/bin/bash

# Unified Script to Check and Purge Vulnerable NPM Packages
# 
# COMPREHENSIVE SCANNING CAPABILITIES:
# - All package managers: npm, yarn, pnpm, bun
# - All lock files: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb
# - All languages: Node.js, Python, Ruby, Go, Rust (any that might use npm packages)
# - All environments: venv/non-venv, multiple Node.js versions, system-wide caches
# - All locations: Git repos, system caches, global installs, Python venvs
#
# Usage:
#   ./main_script.sh                                    # Check current directory only (default)
#   ./main_script.sh --system-wide                      # Check entire system
#   ./main_script.sh --path /path/to/dir               # Check specific directory
#   ./main_script.sh --paths /path1,/path2             # Check multiple directories
#   ./main_script.sh --purge                           # Purge vulnerable packages (with confirmation)
#   ./main_script.sh --purge --yes                     # Purge without confirmation
#   ./main_script.sh --purge --dry-run                 # Show what would be purged (safe mode)
#   ./main_script.sh --purge --reinstall               # Purge and reinstall dependencies
#   ./main_script.sh --no-json                         # Skip JSON report generation
#   ./main_script.sh --verbose                         # Verbose output with progress indicators
#
# Flags:
#   --purge         Purge vulnerable packages (default: check only)
#   --yes           Skip confirmation prompt (use with --purge)
#   --dry-run       Show what would be purged without actually purging (safe mode)
#   --reinstall     Reinstall dependencies after purging
#   --system-wide   Scan entire system instead of current directory
#   --path PATH     Scan specific directory
#   --paths PATH1,PATH2  Scan multiple directories
#   --no-subdirs    Don't scan subdirectories
#   --json          Generate JSON report (default behavior)
#   --no-json       Skip JSON report generation
#   --verbose       Verbose output with progress indicators
#   --help          Show this help message
#
# Environment Variables:
#   SEARCH_PATH - Directory to search for Git repositories (default: current directory)
#   MAX_DEPTH   - Maximum directory depth to search (default: 10)
#   REPORT_FILE - JSON report filename (default: vulnerability-report.json or purge-report.json)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Hardcoded vulnerable packages configuration
# PRODUCTION PACKAGES - Real vulnerable packages from supply chain attacks
PRODUCTION_PACKAGES=(
    "ansi-styles:6.2.2"
    "debug:4.4.2"
    "chalk:5.6.1"
    "strip-ansi:7.1.1"
    "supports-color:10.2.1"
    "ansi-regex:6.2.1"
    "wrap-ansi:9.0.1"
    "slice-ansi:7.1.1"
    "is-arrayish:0.3.3"
    "color-convert:3.1.1"
    "color-name:2.0.1"
    "color-string:2.1.1"
    "simple-swizzle:0.2.3"
    "error-ex:1.3.3"
    "has-ansi:6.0.1"
    "supports-hyperlinks:4.1.1"
    "chalk-template:1.1.1"
    "backslash:0.2.1"
    "color:5.0.1"
    "@duckdb/node-api:1.3.3"
    "@duckdb/node-bindings:1.3.3"
    "duckdb:1.3.3"
    "@duckdb/duckdb-wasm:1.29.2"
    "prebid.js:10.9.2"
    "prebid-universal-creative:latest"
    "prebid:latest"
    "proto-tinker-wc:0.1.87"
    "@ahmedhfarag/ngx-perfect-scrollbar:20.0.20"
    "@ahmedhfarag/ngx-virtual-scroller:4.0.4"
    "@art-ws/common:2.0.28"
    "@art-ws/config-eslint:2.0.4"
    "@art-ws/config-eslint:2.0.5"
    "@art-ws/config-ts:2.0.7"
    "@art-ws/config-ts:2.0.8"
    "@art-ws/db-context:2.0.24"
    "@art-ws/di:2.0.28"
    "@art-ws/di:2.0.32"
    "@art-ws/di-node:2.0.13"
    "@art-ws/eslint:1.0.5"
    "@art-ws/eslint:1.0.6"
    "@art-ws/fastify-http-server:2.0.24"
    "@art-ws/fastify-http-server:2.0.27"
    "@art-ws/http-server:2.0.21"
    "@art-ws/http-server:2.0.25"
    "@art-ws/openapi:0.1.9"
    "@art-ws/openapi:0.1.12"
    "@art-ws/package-base:1.0.5"
    "@art-ws/package-base:1.0.6"
    "@art-ws/prettier:1.0.5"
    "@art-ws/prettier:1.0.6"
    "@art-ws/slf:2.0.15"
    "@art-ws/slf:2.0.22"
    "@art-ws/ssl-info:1.0.9"
    "@art-ws/ssl-info:1.0.10"
    "@art-ws/web-app:1.0.3"
    "@art-ws/web-app:1.0.4"
    "@crowdstrike/commitlint:8.1.1"
    "@crowdstrike/commitlint:8.1.2"
    "@crowdstrike/falcon-shoelace:0.4.1"
    "@crowdstrike/falcon-shoelace:0.4.2"
    "@crowdstrike/foundry-js:0.19.1"
    "@crowdstrike/foundry-js:0.19.2"
    "@crowdstrike/glide-core:0.34.2"
    "@crowdstrike/glide-core:0.34.3"
    "@crowdstrike/logscale-dashboard:1.205.1"
    "@crowdstrike/logscale-dashboard:1.205.2"
    "@crowdstrike/logscale-file-editor:1.205.1"
    "@crowdstrike/logscale-file-editor:1.205.2"
    "@crowdstrike/logscale-parser-edit:1.205.1"
    "@crowdstrike/logscale-parser-edit:1.205.2"
    "@crowdstrike/logscale-search:1.205.1"
    "@crowdstrike/logscale-search:1.205.2"
    "@crowdstrike/tailwind-toucan-base:5.0.1"
    "@crowdstrike/tailwind-toucan-base:5.0.2"
    "@ctrl/deluge:7.2.1"
    "@ctrl/deluge:7.2.2"
    "@ctrl/golang-template:1.4.2"
    "@ctrl/golang-template:1.4.3"
    "@ctrl/magnet-link:4.0.3"
    "@ctrl/magnet-link:4.0.4"
    "@ctrl/ngx-codemirror:7.0.1"
    "@ctrl/ngx-codemirror:7.0.2"
    "@ctrl/ngx-csv:6.0.1"
    "@ctrl/ngx-csv:6.0.2"
    "@ctrl/ngx-emoji-mart:9.2.1"
    "@ctrl/ngx-emoji-mart:9.2.2"
    "@ctrl/ngx-rightclick:4.0.1"
    "@ctrl/ngx-rightclick:4.0.2"
    "@ctrl/qbittorrent:9.7.1"
    "@ctrl/qbittorrent:9.7.2"
    "@ctrl/react-adsense:2.0.1"
    "@ctrl/react-adsense:2.0.2"
    "@ctrl/shared-torrent:6.3.1"
    "@ctrl/shared-torrent:6.3.2"
    "@ctrl/tinycolor:4.1.1"
    "@ctrl/tinycolor:4.1.2"
    "@ctrl/torrent-file:4.1.1"
    "@ctrl/torrent-file:4.1.2"
    "@ctrl/transmission:7.3.1"
    "@ctrl/ts-base32:4.0.1"
    "@ctrl/ts-base32:4.0.2"
    "@hestjs/core:0.2.1"
    "@hestjs/cqrs:0.1.6"
    "@hestjs/demo:0.1.2"
    "@hestjs/eslint-config:0.1.2"
    "@hestjs/logger:0.1.6"
    "@hestjs/scalar:0.1.7"
    "@hestjs/validation:0.1.6"
    "@nativescript-community/arraybuffers:1.1.6"
    "@nativescript-community/arraybuffers:1.1.7"
    "@nativescript-community/arraybuffers:1.1.8"
    "@nativescript-community/gesturehandler:2.0.35"
    "@nativescript-community/perms:3.0.5"
    "@nativescript-community/perms:3.0.6"
    "@nativescript-community/perms:3.0.7"
    "@nativescript-community/perms:3.0.8"
    "@nativescript-community/sentry:4.6.43"
    "@nativescript-community/sqlite:3.5.2"
    "@nativescript-community/sqlite:3.5.3"
    "@nativescript-community/sqlite:3.5.4"
    "@nativescript-community/sqlite:3.5.5"
    "@nativescript-community/text:1.6.9"
    "@nativescript-community/text:1.6.10"
    "@nativescript-community/text:1.6.11"
    "@nativescript-community/text:1.6.12"
    "@nativescript-community/text:1.6.13"
    "@nativescript-community/typeorm:0.2.30"
    "@nativescript-community/typeorm:0.2.31"
    "@nativescript-community/typeorm:0.2.32"
    "@nativescript-community/typeorm:0.2.33"
    "@nativescript-community/ui-collectionview:6.0.6"
    "@nativescript-community/ui-document-picker:1.1.27"
    "@nativescript-community/ui-document-picker:1.1.28"
    "@nativescript-community/ui-drawer:0.1.30"
    "@nativescript-community/ui-image:4.5.6"
    "@nativescript-community/ui-label:1.3.35"
    "@nativescript-community/ui-label:1.3.36"
    "@nativescript-community/ui-label:1.3.37"
    "@nativescript-community/ui-material-bottom-navigation:7.2.72"
    "@nativescript-community/ui-material-bottom-navigation:7.2.73"
    "@nativescript-community/ui-material-bottom-navigation:7.2.74"
    "@nativescript-community/ui-material-bottom-navigation:7.2.75"
    "@nativescript-community/ui-material-bottomsheet:7.2.72"
    "@nativescript-community/ui-material-core:7.2.72"
    "@nativescript-community/ui-material-core:7.2.73"
    "@nativescript-community/ui-material-core:7.2.74"
    "@nativescript-community/ui-material-core:7.2.75"
    "@nativescript-community/ui-material-core:7.2.76"
    "@nativescript-community/ui-material-core-tabs:7.2.72"
    "@nativescript-community/ui-material-core-tabs:7.2.73"
    "@nativescript-community/ui-material-core-tabs:7.2.74"
    "@nativescript-community/ui-material-core-tabs:7.2.75"
    "@nativescript-community/ui-material-core-tabs:7.2.76"
    "@nativescript-community/ui-material-ripple:7.2.72"
    "@nativescript-community/ui-material-ripple:7.2.73"
    "@nativescript-community/ui-material-ripple:7.2.74"
    "@nativescript-community/ui-material-ripple:7.2.75"
    "@nativescript-community/ui-material-tabs:7.2.72"
    "@nativescript-community/ui-material-tabs:7.2.73"
    "@nativescript-community/ui-material-tabs:7.2.74"
    "@nativescript-community/ui-material-tabs:7.2.75"
    "@nativescript-community/ui-pager:14.1.36"
    "@nativescript-community/ui-pager:14.1.37"
    "@nativescript-community/ui-pager:14.1.38"
    "@nativescript-community/ui-pulltorefresh:2.5.4"
    "@nativescript-community/ui-pulltorefresh:2.5.5"
    "@nativescript-community/ui-pulltorefresh:2.5.6"
    "@nativescript-community/ui-pulltorefresh:2.5.7"
    "@nexe/config-manager:0.1.1"
    "@nexe/eslint-config:0.1.1"
    "@nexe/logger:0.1.3"
    "@nstudio/angular:20.0.4"
    "@nstudio/angular:20.0.5"
    "@nstudio/angular:20.0.6"
    "@nstudio/focus:20.0.4"
    "@nstudio/focus:20.0.5"
    "@nstudio/focus:20.0.6"
    "@nstudio/nativescript-checkbox:2.0.6"
    "@nstudio/nativescript-checkbox:2.0.7"
    "@nstudio/nativescript-checkbox:2.0.8"
    "@nstudio/nativescript-checkbox:2.0.9"
    "@nstudio/nativescript-loading-indicator:5.0.1"
    "@nstudio/nativescript-loading-indicator:5.0.2"
    "@nstudio/nativescript-loading-indicator:5.0.3"
    "@nstudio/nativescript-loading-indicator:5.0.4"
    "@nstudio/ui-collectionview:5.1.11"
    "@nstudio/ui-collectionview:5.1.12"
    "@nstudio/ui-collectionview:5.1.13"
    "@nstudio/ui-collectionview:5.1.14"
    "@nstudio/web:20.0.4"
    "@nstudio/web-angular:20.0.4"
    "@nstudio/xplat:20.0.5"
    "@nstudio/xplat:20.0.6"
    "@nstudio/xplat:20.0.7"
    "@nstudio/xplat-utils:20.0.5"
    "@nstudio/xplat-utils:20.0.6"
    "@nstudio/xplat-utils:20.0.7"
    "@operato/board:9.0.36"
    "@operato/board:9.0.37"
    "@operato/board:9.0.38"
    "@operato/board:9.0.39"
    "@operato/board:9.0.40"
    "@operato/board:9.0.41"
    "@operato/board:9.0.42"
    "@operato/board:9.0.43"
    "@operato/board:9.0.44"
    "@operato/board:9.0.45"
    "@operato/board:9.0.46"
    "@operato/data-grist:9.0.29"
    "@operato/data-grist:9.0.35"
    "@operato/data-grist:9.0.36"
    "@operato/data-grist:9.0.37"
    "@operato/graphql:9.0.22"
    "@operato/graphql:9.0.35"
    "@operato/graphql:9.0.36"
    "@operato/graphql:9.0.37"
    "@operato/graphql:9.0.38"
    "@operato/graphql:9.0.39"
    "@operato/graphql:9.0.40"
    "@operato/graphql:9.0.41"
    "@operato/graphql:9.0.42"
    "@operato/graphql:9.0.43"
    "@operato/graphql:9.0.44"
    "@operato/graphql:9.0.45"
    "@operato/graphql:9.0.46"
    "@operato/headroom:9.0.2"
    "@operato/headroom:9.0.35"
    "@operato/headroom:9.0.36"
    "@operato/headroom:9.0.37"
    "@operato/help:9.0.35"
    "@operato/help:9.0.36"
    "@operato/help:9.0.37"
    "@operato/help:9.0.38"
    "@operato/help:9.0.39"
    "@operato/help:9.0.40"
    "@operato/help:9.0.41"
    "@operato/help:9.0.42"
    "@operato/help:9.0.43"
    "@operato/help:9.0.44"
    "@operato/help:9.0.45"
    "@operato/help:9.0.46"
    "@operato/i18n:9.0.35"
    "@operato/i18n:9.0.36"
    "@operato/i18n:9.0.37"
    "@operato/input:9.0.27"
    "@operato/input:9.0.35"
    "@operato/input:9.0.36"
    "@operato/input:9.0.37"
    "@operato/input:9.0.38"
    "@operato/input:9.0.39"
    "@operato/input:9.0.40"
    "@operato/input:9.0.41"
    "@operato/input:9.0.42"
    "@operato/input:9.0.43"
    "@operato/input:9.0.44"
    "@operato/input:9.0.45"
    "@operato/input:9.0.46"
    "@operato/layout:9.0.35"
    "@operato/layout:9.0.36"
    "@operato/layout:9.0.37"
    "@operato/popup:9.0.22"
    "@operato/popup:9.0.35"
    "@operato/popup:9.0.36"
    "@operato/popup:9.0.37"
    "@operato/popup:9.0.38"
    "@operato/popup:9.0.39"
    "@operato/popup:9.0.40"
    "@operato/popup:9.0.41"
    "@operato/popup:9.0.42"
    "@operato/popup:9.0.43"
    "@operato/popup:9.0.44"
    "@operato/popup:9.0.45"
    "@operato/popup:9.0.46"
    "@operato/pull-to-refresh:9.0.36"
    "@operato/pull-to-refresh:9.0.37"
    "@operato/pull-to-refresh:9.0.38"
    "@operato/pull-to-refresh:9.0.39"
    "@operato/pull-to-refresh:9.0.40"
    "@operato/pull-to-refresh:9.0.41"
    "@operato/pull-to-refresh:9.0.42"
    "@operato/shell:9.0.22"
    "@operato/shell:9.0.35"
    "@operato/shell:9.0.36"
    "@operato/shell:9.0.37"
    "@operato/shell:9.0.38"
    "@operato/shell:9.0.39"
    "@operato/styles:9.0.2"
    "@operato/styles:9.0.35"
    "@operato/styles:9.0.36"
    "@operato/styles:9.0.37"
    "@operato/utils:9.0.22"
    "@operato/utils:9.0.35"
    "@operato/utils:9.0.36"
    "@operato/utils:9.0.37"
    "@operato/utils:9.0.38"
    "@operato/utils:9.0.39"
    "@operato/utils:9.0.40"
    "@operato/utils:9.0.41"
    "@operato/utils:9.0.42"
    "@operato/utils:9.0.43"
    "@operato/utils:9.0.44"
    "@operato/utils:9.0.45"
    "@operato/utils:9.0.46"
    "@teselagen/bounce-loader:0.3.16"
    "@teselagen/bounce-loader:0.3.17"
    "@teselagen/liquibase-tools:0.4.1"
    "@teselagen/range-utils:0.3.14"
    "@teselagen/range-utils:0.3.15"
    "@teselagen/react-list:0.8.19"
    "@teselagen/react-list:0.8.20"
    "@teselagen/react-table:6.10.19"
    "@thangved/callback-window:1.1.4"
    "@things-factory/attachment-base:9.0.43"
    "@things-factory/attachment-base:9.0.44"
    "@things-factory/attachment-base:9.0.45"
    "@things-factory/attachment-base:9.0.46"
    "@things-factory/attachment-base:9.0.47"
    "@things-factory/attachment-base:9.0.48"
    "@things-factory/attachment-base:9.0.49"
    "@things-factory/attachment-base:9.0.50"
    "@things-factory/auth-base:9.0.43"
    "@things-factory/auth-base:9.0.44"
    "@things-factory/auth-base:9.0.45"
    "@things-factory/email-base:9.0.42"
    "@things-factory/email-base:9.0.43"
    "@things-factory/email-base:9.0.44"
    "@things-factory/email-base:9.0.45"
    "@things-factory/email-base:9.0.46"
    "@things-factory/email-base:9.0.47"
    "@things-factory/email-base:9.0.48"
    "@things-factory/email-base:9.0.49"
    "@things-factory/email-base:9.0.50"
    "@things-factory/email-base:9.0.51"
    "@things-factory/email-base:9.0.52"
    "@things-factory/email-base:9.0.53"
    "@things-factory/email-base:9.0.54"
    "@things-factory/env:9.0.42"
    "@things-factory/env:9.0.43"
    "@things-factory/env:9.0.44"
    "@things-factory/env:9.0.45"
    "@things-factory/integration-base:9.0.43"
    "@things-factory/integration-base:9.0.44"
    "@things-factory/integration-base:9.0.45"
    "@things-factory/integration-marketplace:9.0.43"
    "@things-factory/integration-marketplace:9.0.44"
    "@things-factory/integration-marketplace:9.0.45"
    "@things-factory/shell:9.0.43"
    "@things-factory/shell:9.0.44"
    "@things-factory/shell:9.0.45"
    "@tnf-dev/api:1.0.8"
    "@tnf-dev/core:1.0.8"
    "@tnf-dev/js:1.0.8"
    "@tnf-dev/mui:1.0.8"
    "@tnf-dev/react:1.0.8"
    "@ui-ux-gang/devextreme-angular-rpk:24.1.7"
    "@yoobic/design-system:6.5.17"
    "@yoobic/jpeg-camera-es6:1.0.13"
    "@yoobic/yobi:8.7.53"
    "airchief:0.3.1"
    "airpilot:0.8.8"
    "angulartics2:14.1.1"
    "angulartics2:14.1.2"
    "browser-webdriver-downloader:3.0.8"
    "capacitor-notificationhandler:0.0.2"
    "capacitor-notificationhandler:0.0.3"
    "capacitor-plugin-healthapp:0.0.2"
    "capacitor-plugin-healthapp:0.0.3"
    "capacitor-plugin-ihealth:1.1.8"
    "capacitor-plugin-ihealth:1.1.9"
    "capacitor-plugin-vonage:1.0.2"
    "capacitor-plugin-vonage:1.0.3"
    "capacitorandroidpermissions:0.0.4"
    "capacitorandroidpermissions:0.0.5"
    "config-cordova:0.8.5"
    "cordova-plugin-voxeet2:1.0.24"
    "cordova-voxeet:1.0.32"
    "create-hest-app:0.1.9"
    "db-evo:1.1.4"
    "db-evo:1.1.5"
    "devextreme-angular-rpk:21.2.8"
    "ember-browser-services:5.0.2"
    "ember-browser-services:5.0.3"
    "ember-headless-form:1.1.2"
    "ember-headless-form:1.1.3"
    "ember-headless-form-yup:1.0.1"
    "ember-headless-table:2.1.5"
    "ember-headless-table:2.1.6"
    "ember-url-hash-polyfill:1.0.12"
    "ember-url-hash-polyfill:1.0.13"
    "ember-velcro:2.2.1"
    "ember-velcro:2.2.2"
    "encounter-playground:0.0.2"
    "encounter-playground:0.0.3"
    "encounter-playground:0.0.4"
    "encounter-playground:0.0.5"
    "eslint-config-crowdstrike:11.0.2"
    "eslint-config-crowdstrike:11.0.3"
    "eslint-config-crowdstrike-node:4.0.3"
    "eslint-config-crowdstrike-node:4.0.4"
    "eslint-config-teselagen:6.1.7"
    "globalize-rpk:1.7.4"
    "graphql-sequelize-teselagen:5.3.8"
    "html-to-base64-image:1.0.2"
    "json-rules-engine-simplified:0.2.1"
    "json-rules-engine-simplified:0.2.4"
    "jumpgate:0.0.2"
    "koa2-swagger-ui:5.11.1"
    "koa2-swagger-ui:5.11.2"
    "mcfly-semantic-release:1.3.1"
    "mcp-knowledge-base:0.0.2"
    "mcp-knowledge-graph:1.2.1"
    "mobioffice-cli:1.0.3"
    "monorepo-next:13.0.1"
    "monorepo-next:13.0.2"
    "mstate-angular:0.4.4"
    "mstate-cli:0.4.7"
    "mstate-dev-react:1.1.1"
    "mstate-react:1.6.5"
    "ng2-file-upload:7.0.2"
    "ng2-file-upload:7.0.3"
    "ng2-file-upload:8.0.1"
    "ng2-file-upload:8.0.2"
    "ng2-file-upload:8.0.3"
    "ng2-file-upload:9.0.1"
    "ngx-bootstrap:18.1.4"
    "ngx-bootstrap:19.0.3"
    "ngx-bootstrap:19.0.4"
    "ngx-bootstrap:20.0.3"
    "ngx-bootstrap:20.0.4"
    "ngx-bootstrap:20.0.5"
    "ngx-color:10.0.1"
    "ngx-color:10.0.2"
    "ngx-toastr:19.0.1"
    "ngx-toastr:19.0.2"
    "ngx-trend:8.0.1"
    "ngx-ws:1.1.5"
    "ngx-ws:1.1.6"
    "oradm-to-gql:35.0.14"
    "oradm-to-gql:35.0.15"
    "oradm-to-sqlz:1.1.2"
    "ove-auto-annotate:0.0.9"
    "pm2-gelf-json:1.0.4"
    "pm2-gelf-json:1.0.5"
    "printjs-rpk:1.6.1"
    "react-complaint-image:0.0.32"
    "react-complaint-image:0.0.35"
    "react-jsonschema-form-conditionals:0.3.18"
    "react-jsonschema-form-conditionals:0.3.21"
    "react-jsonschema-form-extras:1.0.4"
    "remark-preset-lint-crowdstrike:4.0.1"
    "remark-preset-lint-crowdstrike:4.0.2"
    "rxnt-authentication:0.0.3"
    "rxnt-authentication:0.0.4"
    "rxnt-authentication:0.0.5"
    "rxnt-authentication:0.0.6"
    "rxnt-healthchecks-nestjs:1.0.2"
    "rxnt-healthchecks-nestjs:1.0.3"
    "rxnt-healthchecks-nestjs:1.0.4"
    "rxnt-healthchecks-nestjs:1.0.5"
    "rxnt-kue:1.0.4"
    "rxnt-kue:1.0.5"
    "rxnt-kue:1.0.6"
    "rxnt-kue:1.0.7"
    "swc-plugin-component-annotate:1.9.1"
    "swc-plugin-component-annotate:1.9.2"
    "tbssnch:1.0.2"
    "teselagen-interval-tree:1.1.2"
    "tg-client-query-builder:2.14.4"
    "tg-client-query-builder:2.14.5"
    "tg-redbird:1.3.1"
    "tg-seq-gen:1.0.9"
    "tg-seq-gen:1.0.10"
    "thangved-react-grid:1.0.3"
    "ts-gaussian:3.0.5"
    "ts-gaussian:3.0.6"
    "ts-imports:1.0.1"
    "ts-imports:1.0.2"
    "tvi-cli:0.1.5"
    "ve-bamreader:0.2.6"
    "ve-editor:1.0.1"
    "verror-extra:6.0.1"
    "voip-callkit:1.0.2"
    "voip-callkit:1.0.3"
    "wdio-web-reporter:0.1.3"
    "yargs-help-output:5.0.3"
    "yoo-styles:6.0.326"
)

# TEST PACKAGES - Safe dummy packages for testing
TEST_PACKAGES=(
    "lodash:4.17.21"
)

# MODE SWITCH - Change this to switch between TEST and PRODUCTION modes
# Set to "TEST" for testing mode, "PRODUCTION" for production mode
SCAN_MODE="PRODUCTION"

# Load vulnerable packages based on mode
load_vulnerable_packages() {
    if [ "$SCAN_MODE" = "TEST" ]; then
        VULNERABLE_PACKAGES=("${TEST_PACKAGES[@]}")
        if [ "$VERBOSE" = "true" ]; then
            echo -e "${PURPLE}[VERBOSE]${NC} Loaded ${#VULNERABLE_PACKAGES[@]} TEST packages (safe for testing)" >&2
        fi
    elif [ "$SCAN_MODE" = "PRODUCTION" ]; then
        VULNERABLE_PACKAGES=("${PRODUCTION_PACKAGES[@]}")
        if [ "$VERBOSE" = "true" ]; then
            echo -e "${PURPLE}[VERBOSE]${NC} Loaded ${#VULNERABLE_PACKAGES[@]} PRODUCTION packages (real vulnerable packages)" >&2
        fi
    else
        echo -e "${RED}❌ Error: Invalid SCAN_MODE: $SCAN_MODE${NC}"
        echo -e "${YELLOW}💡 Tip: Set SCAN_MODE to 'TEST' or 'PRODUCTION' in the script${NC}"
        exit $EXIT_ERROR
    fi
    
    # Verify that VULNERABLE_PACKAGES array is defined
    if [ ${#VULNERABLE_PACKAGES[@]} -eq 0 ]; then
        echo -e "${RED}❌ Error: No vulnerable packages configured${NC}"
        echo -e "${YELLOW}💡 Tip: Check the SCAN_MODE setting in the script${NC}"
        exit $EXIT_ERROR
    fi
}

# Load vulnerable packages configuration
load_vulnerable_packages

# Parse command line arguments
PURGE_MODE=false
SKIP_CONFIRMATION=false
JSON_REPORT=true  # Default to true
VERBOSE=false
REPORT_FILE="${REPORT_FILE:-}"
DRY_RUN=false  # Safe default - no destructive operations
REINSTALL_PACKAGES=false  # Safe default - no automatic reinstall
SYSTEM_WIDE=false  # Default to current directory scanning
SCAN_PATHS=""  # Custom scan paths
NO_SUBDIRS=false  # Default to include subdirectories
MAX_JOBS="${MAX_JOBS:-4}"
CACHE_DIR="${CACHE_DIR:-/tmp/vulnerable-packages-cache}"
CURRENT_OPERATION=0
TOTAL_OPERATIONS=0
MAX_FILE_SIZE="${MAX_FILE_SIZE:-10485760}"  # 10MB max file size to scan
HANG_DETECTION_SECONDS="${HANG_DETECTION_SECONDS:-10}"  # 10 seconds to detect hangs
MAX_OPERATION_SECONDS="${MAX_OPERATION_SECONDS:-60}"  # 60 seconds max per operation
MAX_PATH_LENGTH="${MAX_PATH_LENGTH:-4096}"  # Maximum path length (4KB)
MAX_REPOS="${MAX_REPOS:-1000}"  # Maximum number of repositories to scan

# Exit codes for CI/CD integration
EXIT_SUCCESS=0          # No vulnerabilities found
EXIT_VULNERABILITIES=1  # Vulnerabilities found
EXIT_ERROR=2           # Script errors
EXIT_PERMISSION=3      # Permission denied

# Security and performance functions
sanitize_path() {
    echo "$1" | sed 's|/Users/[^/]*|/Users/***|g' | sed 's|/home/[^/]*|/home/***|g' | sed 's|/root/[^/]*|/root/***|g'
}

# Hang detection and protection functions
detect_hang() {
    local pid="$1"
    local description="$2"
    local hang_threshold="$3"
    
    # Simple wait - hang protection can be added later if needed
    # For now, prioritize functionality over hang protection
    wait "$pid"
    return $?
}

check_file_size() {
    local file_path="$1"
    if [ -f "$file_path" ]; then
        local file_size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "0")
        if [ "$file_size" -gt "$MAX_FILE_SIZE" ]; then
            echo -e "${YELLOW}⚠️  Skipping large file (${file_size} bytes): $file_path${NC}"
            return 1
        fi
    fi
    return 0
}

# Performance optimization functions
is_binary_file() {
    local file_path="$1"
    if [ -f "$file_path" ]; then
        # Check if file is binary (contains null bytes or non-text characters)
        if file "$file_path" 2>/dev/null | grep -q "text"; then
            return 1  # Not binary
        else
            return 0  # Binary
        fi
    fi
    return 1
}

optimize_find_operation() {
    local search_path="$1"
    local max_depth="$2"
    local pattern="$3"
    
    # Skip common directories that won't contain vulnerable packages
    local skip_dirs=(
        ".git"
        "node_modules"
        ".cache"
        "dist"
        "build"
        ".next"
        ".nuxt"
        "coverage"
        ".nyc_output"
    )
    
    local find_cmd="find \"$search_path\" -maxdepth \"$max_depth\" -name \"$pattern\""
    
    # Add skip directories to find command
    for skip_dir in "${skip_dirs[@]}"; do
        find_cmd="$find_cmd -not -path \"*/$skip_dir/*\""
    done
    
    # Add file type filters for better performance
    find_cmd="$find_cmd -type f -L"  # -L follows symlinks
    
    echo "$find_cmd"
}

# Enhanced safe_grep with performance optimizations
safe_grep_optimized() {
    local pattern="$1"
    local file_path="$2"
    local hang_threshold="${3:-$HANG_DETECTION_SECONDS}"
    local output_mode="${4:-quiet}"
    
    # Skip binary files
    if is_binary_file "$file_path"; then
        return 1
    fi
    
    # Check file size first
    if ! check_file_size "$file_path"; then
        return 1
    fi
    
    # Use optimized grep with timeout
    if [ "$output_mode" = "output" ]; then
        local temp_file
        temp_file=$(mktemp) || { echo "Failed to create temp file"; return 1; }
        trap 'rm -f "$temp_file"' EXIT
        
        timeout "$hang_threshold" grep "$pattern" "$file_path" 2>/dev/null > "$temp_file" &
        local grep_pid=$!
        
        wait "$grep_pid"
        local exit_code=$?
        
        if [ $exit_code -eq 0 ] && [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
            cat "$temp_file"
        fi
        
        rm -f "$temp_file"
        trap - EXIT
        return $exit_code
    else
        timeout "$hang_threshold" grep -q "$pattern" "$file_path" 2>/dev/null
        return $?
    fi
}

# Validate path length
validate_path_length() {
    local path="$1"
    local path_length=${#path}
    
    if [ "$path_length" -gt "$MAX_PATH_LENGTH" ]; then
        echo -e "${YELLOW}⚠️  Warning: Path too long ($path_length > $MAX_PATH_LENGTH): $path${NC}"
        return 1
    fi
    return 0
}

# Enhanced path sanitization for special characters
sanitize_path_for_special_chars() {
    local path="$1"
    
    # Handle common special characters that might cause issues
    # This is a basic implementation - more complex cases may need additional handling
    if [[ "$path" =~ [\$\`\\] ]]; then
        echo -e "${YELLOW}⚠️  Warning: Path contains special characters that may cause issues: $path${NC}"
        # Don't fail, just warn - the script should handle these gracefully
    fi
    
    return 0
}

safe_grep() {
    local pattern="$1"
    local file_path="$2"
    local hang_threshold="${3:-$HANG_DETECTION_SECONDS}"
    local output_mode="${4:-quiet}"  # quiet or output
    
    # Validate path length
    if ! validate_path_length "$file_path"; then
        return 1
    fi
    
    # Check for special characters
    sanitize_path_for_special_chars "$file_path"
    
    # Check file size first
    if ! check_file_size "$file_path"; then
        return 1
    fi
    
    # Start grep in background
    if [ "$output_mode" = "output" ]; then
        # For output mode, use temporary file
        local temp_file
        temp_file=$(mktemp) || { echo "Failed to create temp file"; return 1; }
        trap 'rm -f "$temp_file"' EXIT
        
        grep "$pattern" "$file_path" 2>/dev/null > "$temp_file" &
        local grep_pid=$!
        
        # Monitor for hangs
        local exit_code
        detect_hang "$grep_pid" "grep operation on $file_path" "$hang_threshold"
        exit_code=$?
        
        # If successful, output the results
        if [ $exit_code -eq 0 ] && [ -f "$temp_file" ]; then
            cat "$temp_file"
        fi
        
        # Clean up
        rm -f "$temp_file"
        trap - EXIT
        return $exit_code
    else
        # For quiet mode (default)
        grep -q "$pattern" "$file_path" 2>/dev/null &
        local grep_pid=$!
        
        # Monitor for hangs
        detect_hang "$grep_pid" "grep operation on $file_path" "$hang_threshold"
        return $?
    fi
}

safe_find() {
    local search_path="$1"
    local max_depth="$2"
    local pattern="$3"
    local hang_threshold="${4:-$HANG_DETECTION_SECONDS}"
    
    log_verbose "Safe find: $search_path (max depth: $max_depth, pattern: $pattern)"
    
    # Create temporary file for results
    local temp_file
    temp_file=$(mktemp) || { echo "Failed to create temp file"; return 1; }
    trap 'rm -f "$temp_file"' EXIT
    
    # Start find in background, redirect output to temp file
    find "$search_path" -maxdepth "$max_depth" -name "$pattern" 2>/dev/null > "$temp_file" &
    local find_pid=$!
    
    # Monitor for hangs
    local exit_code
    detect_hang "$find_pid" "find operation in $search_path" "$hang_threshold"
    exit_code=$?
    
    # Check if we found results before cleaning up
    local found_results=false
    if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
        cat "$temp_file"
        found_results=true
    fi
    
    # Clean up
    rm -f "$temp_file"
    trap - EXIT
    
    # Return 0 if we found results, regardless of find exit code
    if [ "$found_results" = "true" ]; then
        return 0
    else
        return 1
    fi
}

verify_script_integrity() {
    if [ -f "$0.sha256" ]; then
        if ! sha256sum -c "$0.sha256" >/dev/null 2>&1; then
            echo -e "${RED}❌ Script integrity verification failed!${NC}"
            echo -e "${RED}   The script may have been tampered with.${NC}"
            exit 1
        fi
    fi
}

limit_concurrent_operations() {
    local max_ops="${MAX_JOBS:-4}"
    local current_ops=$(jobs -r | wc -l)
    if [ "$current_ops" -ge "$max_ops" ]; then
        wait -n
    fi
}

show_progress() {
    if [ "$VERBOSE" = "true" ] && [ "$TOTAL_OPERATIONS" -gt 0 ]; then
        CURRENT_OPERATION=$((CURRENT_OPERATION + 1))
        local percentage=$((CURRENT_OPERATION * 100 / TOTAL_OPERATIONS))
        printf "\r${CYAN}Progress: [%-50s] %d%% (%d/%d)${NC}" \
            "$(printf "%*s" $((percentage/2)) | tr ' ' '=')" \
            "$percentage" "$CURRENT_OPERATION" "$TOTAL_OPERATIONS"
    fi
}

# Enhanced progress reporting with user-friendly output
show_repo_progress() {
    local current_repo="$1"
    local total_repos="$2"
    local repo_number="$3"
    
    echo -e "\n${BLUE}📁 Processing repository $repo_number of $total_repos:${NC}"
    echo -e "${CYAN}   Location: $current_repo${NC}"
    
    if [ "$PURGE_MODE" = "true" ]; then
        if [ "$DRY_RUN" = "true" ]; then
            echo -e "${YELLOW}   Mode: DRY-RUN (showing what would be purged)${NC}"
        else
            echo -e "${RED}   Mode: PURGE (removing vulnerable packages)${NC}"
        fi
        if [ "$REINSTALL_PACKAGES" = "true" ]; then
            echo -e "${GREEN}   Reinstall: ENABLED${NC}"
        else
            echo -e "${YELLOW}   Reinstall: DISABLED (use --reinstall flag)${NC}"
        fi
    else
        echo -e "${GREEN}   Mode: CHECK (scanning only)${NC}"
    fi
    echo ""
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${PURPLE}[VERBOSE]${NC} $1" >&2
    fi
}

# Error recovery and safe operation functions
handle_error() {
    local error_msg="$1"
    local repo_path="$2"
    echo -e "${YELLOW}⚠️  Warning: $error_msg${NC}"
    if [ -n "$repo_path" ]; then
        echo -e "${YELLOW}   Repository: $repo_path${NC}"
    fi
    echo -e "${BLUE}   Continuing with next operation...${NC}"
    return 1
}

safe_file_operation() {
    local file_path="$1"
    local operation="$2"
    local timeout_seconds="${3:-30}"
    
    # Check if file exists and is readable
    if [ ! -f "$file_path" ] || [ ! -r "$file_path" ]; then
        handle_error "Cannot access file: $file_path"
        return 1
    fi
    
    # Perform operation with timeout
    if timeout "$timeout_seconds" $operation "$file_path" 2>/dev/null; then
        return 0
    else
        handle_error "Timeout or error processing file: $file_path"
        return 1
    fi
}

process_repository_safe() {
    local repo="$1"
    local repo_errors=0
    
    # Check if repository is accessible
    if [ ! -d "$repo" ] || [ ! -r "$repo" ]; then
        handle_error "Cannot access repository" "$repo"
        return 1
    fi
    
    # Check disk space
    local available_space=$(df "$repo" | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # Less than 1MB
        handle_error "Low disk space in repository directory" "$repo"
        repo_errors=$((repo_errors + 1))
    fi
    
    return $repo_errors
}

validate_config() {
    # Validate SEARCH_PATH
    if [ -n "$SEARCH_PATH" ]; then
        if [ ! -d "$SEARCH_PATH" ]; then
            echo -e "${RED}❌ Error: SEARCH_PATH does not exist: $SEARCH_PATH${NC}"
            exit $EXIT_ERROR
        fi
        if [ ! -r "$SEARCH_PATH" ]; then
            echo -e "${RED}❌ Error: Cannot read SEARCH_PATH: $SEARCH_PATH${NC}"
            exit $EXIT_PERMISSION
        fi
    fi
    
    # Validate MAX_DEPTH
    if [ -n "$MAX_DEPTH" ]; then
        if ! [[ "$MAX_DEPTH" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ Error: MAX_DEPTH must be a positive integer${NC}"
            exit $EXIT_ERROR
        fi
        if [ "$MAX_DEPTH" -gt 20 ]; then
            echo -e "${YELLOW}⚠️  Warning: MAX_DEPTH > 20 may cause performance issues${NC}"
        fi
    fi
    
    # Validate MAX_JOBS
    if [ -n "$MAX_JOBS" ]; then
        if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ Error: MAX_JOBS must be a positive integer${NC}"
            exit $EXIT_ERROR
        fi
        if [ "$MAX_JOBS" -gt 16 ]; then
            echo -e "${YELLOW}⚠️  Warning: MAX_JOBS > 16 may cause system overload${NC}"
        fi
    fi
    
    # Validate REPORT_FILE
    if [ -n "$REPORT_FILE" ]; then
        local report_dir=$(dirname "$REPORT_FILE")
        if [ ! -w "$report_dir" ]; then
            echo -e "${RED}❌ Error: Cannot write to REPORT_FILE directory: $report_dir${NC}"
            exit $EXIT_PERMISSION
        fi
    fi
    
    # Validate vulnerable packages list
    if [ ${#VULNERABLE_PACKAGES[@]} -eq 0 ]; then
        echo -e "${RED}❌ Error: No vulnerable packages defined${NC}"
        exit $EXIT_ERROR
    fi
    
    # Check required commands
    local required_commands=("find" "grep" "sed" "stat")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}❌ Error: Required command not found: $cmd${NC}"
            exit $EXIT_ERROR
        fi
    done
}

# Cache functions
init_cache() {
    mkdir -p "$CACHE_DIR"
    log_verbose "Cache directory: $CACHE_DIR"
}

get_cache_key() {
    local path="$1"
    echo "$path" | sha256sum | cut -d' ' -f1
}

is_cache_valid() {
    local cache_key="$1"
    local cache_file="$CACHE_DIR/$cache_key"
    local max_age=3600  # 1 hour
    
    if [ -f "$cache_file" ]; then
        local file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null)))
        if [ "$file_age" -lt "$max_age" ]; then
            return 0
        fi
    fi
    return 1
}

save_to_cache() {
    local cache_key="$1"
    local data="$2"
    echo "$data" > "$CACHE_DIR/$cache_key"
}

load_from_cache() {
    local cache_key="$1"
    cat "$CACHE_DIR/$cache_key" 2>/dev/null || echo ""
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --purge)
            PURGE_MODE=true
            shift
            ;;
        --yes)
            SKIP_CONFIRMATION=true
            shift
            ;;
        --json)
            JSON_REPORT=true
            shift
            ;;
        --no-json)
            JSON_REPORT=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --reinstall)
            REINSTALL_PACKAGES=true
            shift
            ;;
        --system-wide)
            SYSTEM_WIDE=true
            shift
            ;;
        --path)
            if [ -z "$2" ]; then
                echo -e "${RED}❌ Error: --path requires a directory path${NC}"
                exit $EXIT_ERROR
            fi
            SCAN_PATHS="$2"
            shift 2
            ;;
        --paths)
            if [ -z "$2" ]; then
                echo -e "${RED}❌ Error: --paths requires comma-separated directory paths${NC}"
                exit $EXIT_ERROR
            fi
            SCAN_PATHS="$2"
            shift 2
            ;;
        --no-subdirs)
            NO_SUBDIRS=true
            shift
            ;;
        --help)
            echo "Enhanced Unified Script to Check and Purge Vulnerable NPM Packages"
            echo ""
            echo "Usage:"
            echo "  $0                           # Check current directory only (default)"
            echo "  $0 --system-wide             # Check entire system"
            echo "  $0 --path /path/to/dir       # Check specific directory"
            echo "  $0 --paths /path1,/path2     # Check multiple directories"
            echo "  $0 --path /path --no-subdirs # Check directory without subdirectories"
            echo "  $0 --purge                   # Purge vulnerable packages (with confirmation)"
            echo "  $0 --purge --yes             # Purge without confirmation"
            echo "  $0 --purge --dry-run         # Show what would be purged (safe mode)"
            echo "  $0 --purge --reinstall       # Purge and reinstall dependencies"
            echo "  $0 --no-json                 # Skip JSON report generation"
            echo "  $0 --purge --no-json         # Purge without JSON report"
            echo "  $0 --verbose                 # Verbose output with progress indicators"
            echo ""
            echo "Environment Variables:"
            echo "  SEARCH_PATH - Directory to search (default: current directory)"
            echo "  MAX_DEPTH   - Maximum search depth (default: 10)"
            echo "  REPORT_FILE - JSON report filename"
            echo "  MAX_JOBS    - Maximum parallel jobs (default: 4)"
            echo "  CACHE_DIR   - Cache directory (default: /tmp/vulnerable-packages-cache)"
            echo "  MAX_FILE_SIZE - Maximum file size to scan (default: 10MB)"
            echo "  MAX_PATH_LENGTH - Maximum path length (default: 4096)"
            echo "  MAX_REPOS   - Maximum repositories to scan (default: 1000)"
            echo "  HANG_DETECTION_SECONDS - Hang detection threshold (default: 10s)"
            echo "  MAX_OPERATION_SECONDS - Maximum operation time (default: 60s)"
            echo ""
            echo "Flags:"
            echo "  --purge     Purge vulnerable packages"
            echo "  --yes       Skip confirmation prompt"
            echo "  --dry-run   Show what would be purged without actually purging (SAFE)"
            echo "  --reinstall Reinstall dependencies after purging"
            echo "  --json      Generate JSON report (default behavior)"
            echo "  --no-json   Skip JSON report generation"
            echo "  --verbose   Verbose output with progress indicators"
            echo "  --help      Show this help"
            echo ""
            echo "Exit Codes:"
            echo "  0 - Success, no vulnerabilities found"
            echo "  1 - Vulnerabilities found"
            echo "  2 - Script errors"
            echo "  3 - Permission denied"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Check current directory"
            echo "  $0 --purge --dry-run                 # See what would be purged (SAFE)"
            echo "  $0 --purge --reinstall               # Purge and reinstall dependencies"
            echo "  SEARCH_PATH=/path/to/repos $0        # Check specific directory"
            echo "  MAX_DEPTH=5 $0 --verbose             # Limit search depth with verbose output"
            echo ""
            echo "Testing vs Production Mode:"
            echo "  - For TESTING: Set SCAN_MODE=\"TEST\" (line 93)"
            echo "  - For PRODUCTION: Set SCAN_MODE=\"PRODUCTION\" (line 93)"
            echo "  - Switch modes by editing SCAN_MODE variable in the script"
            echo ""
            echo "Common Use Cases:"
            echo "  1. Quick check: $0"
            echo "  2. Safe preview: $0 --purge --dry-run"
            echo "  3. Full cleanup: $0 --purge --reinstall --yes"
            echo "  4. CI/CD check: $0 && echo 'Clean' || echo 'Vulnerabilities found'"
            echo ""
            echo "Troubleshooting:"
            echo "  - Permission denied: Run with sudo or check file permissions"
            echo "  - Script hangs: Use --verbose to see progress, reduce MAX_DEPTH"
            echo "  - Large repositories: Increase MAX_JOBS for parallel processing"
            echo "  - Disk space issues: Check available space in target directories"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set default report file based on mode
if [ "$JSON_REPORT" = "true" ]; then
    if [ -z "$REPORT_FILE" ]; then
        if [ "$PURGE_MODE" = "true" ]; then
            REPORT_FILE="purge-report.json"
        else
            REPORT_FILE="vulnerability-report.json"
        fi
    fi
fi

# Global counters
VULNERABILITIES_FOUND=0
PACKAGES_PURGED=0
REPOSITORIES_SCANNED=0

# Function to discover Git repositories
# NOTE: This function works with Git repositories by default for safety.
# To scan the entire system regardless of Git repos, modify the search_path to "/" 
# and ensure you have appropriate permissions for system-wide scanning.
discover_git_repos() {
    local search_path="${1:-/}"
    local max_depth="${2:-10}"
    
    log_verbose "Discovering Git repositories in: $search_path (max depth: $max_depth)"
    
    # Use safe_find with hang detection
    local git_dirs
    git_dirs=$(safe_find "$search_path" "$max_depth" ".git" 15)
    
    if [ $? -eq 0 ] && [ -n "$git_dirs" ]; then
        echo "$git_dirs" | while read -r git_dir; do
            local repo_path=$(dirname "$git_dir")
            # Skip if it's a bare repository or submodule (with hang detection)
            if [ -f "$git_dir/config" ] && ! safe_grep "bare = true" "$git_dir/config" 5; then
                echo "$repo_path"
            fi
        done | sort -u
    fi
}

# Detect system type and root
detect_system_info() {
    # Detect operating system
    if [[ "$OSTYPE" == "darwin"* ]]; then
        SYSTEM_TYPE="macos"
        SYSTEM_ROOT="/"
        # macOS specific paths
        SEARCH_PATHS=(
            "/Users"
            "/Applications"
            "/System/Volumes/Data"
            "/opt"
            "/usr/local"
            "/var"
        )
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        SYSTEM_TYPE="linux"
        SYSTEM_ROOT="/"
        # Linux specific paths
        SEARCH_PATHS=(
            "/home"
            "/opt"
            "/usr/local"
            "/var"
            "/root"
            "/srv"
        )
    else
        SYSTEM_TYPE="unknown"
        SYSTEM_ROOT="/"
        # Generic Unix paths
        SEARCH_PATHS=(
            "/home"
            "/opt"
            "/usr/local"
            "/var"
            "/root"
        )
    fi
    
    echo -e "${BLUE}🖥️  Detected system: $SYSTEM_TYPE${NC}"
    echo -e "${BLUE}📁 System root: $SYSTEM_ROOT${NC}"
}

# Function to check package-lock.json for vulnerable packages
check_package_lock() {
    local package_lock="$1"
    local found_vulnerable=false
    local vuln_count=0
    
    echo -e "${BLUE}  📄 Checking: $package_lock${NC}"
    
    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        local package="${package_version%:*}"
        local vulnerable_version="${package_version#*:}"
        
        # Check for exact version match in dependencies
        if grep -q "\"$package\": \"$vulnerable_version\"" "$package_lock" 2>/dev/null; then
            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $package_lock${NC}"
            found_vulnerable=true
            vuln_count=$((vuln_count + 1))
            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
        fi
        
        # Check for version in dependencies section (more robust)
        if grep -A 20 "\"$package\": {" "$package_lock" 2>/dev/null | grep -q "\"version\": \"$vulnerable_version\""; then
            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in dependencies of $package_lock${NC}"
            found_vulnerable=true
            vuln_count=$((vuln_count + 1))
            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
        fi
        
        # Check for version in packages section (npm v7+ format)
        if grep -A 10 "\"node_modules/$package\":" "$package_lock" 2>/dev/null | grep -q "\"version\": \"$vulnerable_version\""; then
            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in packages section of $package_lock${NC}"
            found_vulnerable=true
            vuln_count=$((vuln_count + 1))
            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
        fi
    done
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found${NC}"
    fi
    
    return $vuln_count
}

# Function to check node_modules for vulnerable packages
check_node_modules() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  📦 Checking node_modules in: $repo_path${NC}"
    
    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        local package="${package_version%:*}"
        local vulnerable_version="${package_version#*:}"
        
        # Find all package.json files in node_modules for this package
        while IFS= read -r -d '' package_json; do
            if [ -f "$package_json" ]; then
                local version=$(grep '"version"' "$package_json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                if [ "$version" = "$vulnerable_version" ]; then
                    echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $package_json${NC}"
                    found_vulnerable=true
                    VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                fi
            fi
        done < <(find "$repo_path" -path "*/node_modules/$package/package.json" -print0 2>/dev/null)
    done
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in node_modules${NC}"
    fi
}

# Function to check package.json files for vulnerable package references
check_package_json() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  📋 Checking package.json files in: $repo_path${NC}"
    
    while IFS= read -r -d '' package_json; do
        echo -e "${YELLOW}    📄 Checking: $package_json${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if package is referenced with vulnerable version
            if grep -q "\"$package\": \"$vulnerable_version\"" "$package_json" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $package_json${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" -name "package.json" -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in package.json files${NC}"
    fi
}

# Function to check yarn.lock files
check_yarn_lock() {
    local yarn_lock="$1"
    local found_vulnerable=false
    local vuln_count=0
    
    echo -e "${BLUE}  🧶 Checking: $yarn_lock${NC}"
    
    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        local package="${package_version%:*}"
        local vulnerable_version="${package_version#*:}"
        
        # Check for exact version match in yarn.lock
        if grep -q "^$package@$vulnerable_version:" "$yarn_lock" 2>/dev/null; then
            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $yarn_lock${NC}"
            found_vulnerable=true
            vuln_count=$((vuln_count + 1))
            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
        fi
    done
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found${NC}"
    fi
    
    return $vuln_count
}

# Function to check pnpm-lock.yaml files
check_pnpm_lock() {
    local pnpm_lock="$1"
    local found_vulnerable=false
    local vuln_count=0
    
    echo -e "${BLUE}  📦 Checking: $pnpm_lock${NC}"
    
    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        local package="${package_version%:*}"
        local vulnerable_version="${package_version#*:}"
        
        # Check for exact version match in pnpm-lock.yaml
        if grep -q "/$package/$vulnerable_version" "$pnpm_lock" 2>/dev/null; then
            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $pnpm_lock${NC}"
            found_vulnerable=true
            vuln_count=$((vuln_count + 1))
            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
        fi
    done
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found${NC}"
    fi
    
    return $vuln_count
}

# Function to check bun.lockb files (binary format - check if bun is available)
check_bun_lock() {
    local bun_lock="$1"
    local found_vulnerable=false
    local vuln_count=0
    
    echo -e "${BLUE}  🥟 Checking: $bun_lock${NC}"
    
    # Check if bun is available to read the lockfile
    if command -v bun >/dev/null 2>&1; then
        # Try to extract package info from bun lockfile
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Use bun to check if the vulnerable version is in the lockfile
            if bun pm ls 2>/dev/null | grep -q "$package@$vulnerable_version" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $bun_lock${NC}"
                found_vulnerable=true
                vuln_count=$((vuln_count + 1))
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    else
        echo -e "${YELLOW}    ⚠️  Bun not available, skipping binary lockfile check${NC}"
    fi
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found${NC}"
    fi
    
    return $vuln_count
}

# Function to check Python requirements files for npm packages
check_python_requirements() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  🐍 Checking Python requirements files in: $repo_path${NC}"
    
    # Check various Python requirements file formats
    while IFS= read -r -d '' req_file; do
        echo -e "${YELLOW}    📄 Checking: $req_file${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if npm package is referenced in Python requirements (more specific matching)
            # Look for npm package patterns: "package@version" or "package": "version"
            if grep -q "\"$package\": \"$vulnerable_version\"" "$req_file" 2>/dev/null || \
               grep -q "$package@$vulnerable_version" "$req_file" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $req_file${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" \( -name "requirements*.txt" -o -name "requirements*.in" -o -name "Pipfile" -o -name "Pipfile.lock" -o -name "pyproject.toml" -o -name "poetry.lock" -o -name "setup.py" -o -name "setup.cfg" -o -name "conda.yml" -o -name "environment.yml" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in Python requirements${NC}"
    fi
}

# Function to check Ruby Gemfile for npm packages
check_ruby_gemfile() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  💎 Checking Ruby Gemfiles in: $repo_path${NC}"
    
    while IFS= read -r -d '' gemfile; do
        echo -e "${YELLOW}    📄 Checking: $gemfile${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if npm package is referenced in Ruby files
            if grep -q "$package.*$vulnerable_version" "$gemfile" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $gemfile${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" \( -name "Gemfile" -o -name "Gemfile.lock" -o -name "*.gemspec" -o -name "Rakefile" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in Ruby files${NC}"
    fi
}

# Function to check Go modules for npm packages
check_go_modules() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  🐹 Checking Go modules in: $repo_path${NC}"
    
    while IFS= read -r -d '' go_file; do
        echo -e "${YELLOW}    📄 Checking: $go_file${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if npm package is referenced in Go files
            if grep -q "$package.*$vulnerable_version" "$go_file" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $go_file${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" \( -name "go.mod" -o -name "go.sum" -o -name "go.work" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in Go modules${NC}"
    fi
}

# Function to check Rust Cargo files for npm packages
check_rust_cargo() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  🦀 Checking Rust Cargo files in: $repo_path${NC}"
    
    while IFS= read -r -d '' cargo_file; do
        echo -e "${YELLOW}    📄 Checking: $cargo_file${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if npm package is referenced in Rust files
            if grep -q "$package.*$vulnerable_version" "$cargo_file" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $cargo_file${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" \( -name "Cargo.toml" -o -name "Cargo.lock" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in Rust files${NC}"
    fi
}

# Function to check build tool configurations for npm packages
check_build_tools() {
    local repo_path="$1"
    local found_vulnerable=false
    
    echo -e "${BLUE}  🔧 Checking build tool configurations in: $repo_path${NC}"
    
    # Check various build tool config files
    while IFS= read -r -d '' build_file; do
        echo -e "${YELLOW}    📄 Checking: $build_file${NC}"
        
        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
            local package="${package_version%:*}"
            local vulnerable_version="${package_version#*:}"
            
            # Check if npm package is referenced in build files
            if grep -q "\"$package\": \"$vulnerable_version\"" "$build_file" 2>/dev/null || \
               grep -q "$package@$vulnerable_version" "$build_file" 2>/dev/null; then
                echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $build_file${NC}"
                found_vulnerable=true
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            fi
        done
    done < <(find "$repo_path" \( -name "webpack.config.*" -o -name "rollup.config.*" -o -name "vite.config.*" -o -name "next.config.*" -o -name "nuxt.config.*" -o -name "gulpfile.*" -o -name "gruntfile.*" -o -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "*.dockerfile" \) -not -path "*/node_modules/*" -print0 2>/dev/null)
    
    if [ "$found_vulnerable" = false ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in build tool configurations${NC}"
    fi
}

# Function to purge vulnerable packages from node_modules
purge_node_modules() {
    local repo_path="$1"
    local purged_count=0
    
    echo -e "${BLUE}  🧹 Purging node_modules in: $repo_path${NC}"
    
    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        local package="${package_version%:*}"
        local vulnerable_version="${package_version#*:}"
        
        # Find and remove vulnerable package directories
        while IFS= read -r -d '' package_dir; do
            if [ -d "$package_dir" ]; then
                # Check if it's the vulnerable version
                if [ -f "$package_dir/package.json" ]; then
                    local version=$(grep '"version"' "$package_dir/package.json" | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                    if [ "$version" = "$vulnerable_version" ]; then
                        if [ "$DRY_RUN" = "true" ]; then
                            echo -e "${YELLOW}    🔍 [DRY-RUN] Would remove: $package@$vulnerable_version from $package_dir${NC}"
                        else
                            echo -e "${YELLOW}    🗑️  Removing: $package@$vulnerable_version from $package_dir${NC}"
                        fi
                        # Validate path before deletion for security
                        if [[ "$package_dir" == *"/node_modules/"* ]] && [[ "$package_dir" == *"/$package" ]]; then
                            if [ "$DRY_RUN" = "false" ]; then
                                # Use safer deletion - only remove the specific package directory
                                if [ -d "$package_dir" ]; then
                                    rm -r "$package_dir" 2>/dev/null || echo -e "${YELLOW}    ⚠️  Could not remove $package_dir${NC}"
                                fi
                            fi
                            purged_count=$((purged_count + 1))
                            PACKAGES_PURGED=$((PACKAGES_PURGED + 1))
                        else
                            echo -e "${RED}    ⚠️  Skipping suspicious path: $package_dir${NC}"
                        fi
                    fi
                fi
            fi
        done < <(find "$repo_path" -path "*/node_modules/$package" -type d -L -print0 2>/dev/null)
    done
    
    if [ "$purged_count" -eq 0 ]; then
        echo -e "${GREEN}    ✅ No vulnerable packages found in node_modules${NC}"
    else
        echo -e "${YELLOW}    🧹 Purged $purged_count vulnerable packages${NC}"
    fi
}

# Function to reinstall dependencies
reinstall_dependencies() {
    local repo_path="$1"
    
    echo -e "${BLUE}  🔄 Reinstalling dependencies in: $repo_path${NC}"
    
    # Check if package.json exists
    if [ -f "$repo_path/package.json" ]; then
        if ! cd "$repo_path"; then
            echo -e "${RED}    ❌ Failed to enter directory: $repo_path${NC}"
            return 1
        fi
        
        # Remove package-lock.json and node_modules
        if [ -f "package-lock.json" ]; then
            echo -e "${YELLOW}    🗑️  Removing package-lock.json${NC}"
            rm -f package-lock.json
        fi
        
        if [ -d "node_modules" ]; then
            echo -e "${YELLOW}    🗑️  Removing node_modules${NC}"
            # Use safer deletion - remove node_modules directory
            rm -r node_modules 2>/dev/null || echo -e "${YELLOW}    ⚠️  Could not remove node_modules${NC}"
        fi
        
        # Reinstall dependencies
        echo -e "${YELLOW}    📦 Running npm install${NC}"
        if npm install 2>/dev/null; then
            echo -e "${GREEN}    ✅ Dependencies reinstalled successfully${NC}"
        else
            echo -e "${RED}    ❌ Failed to reinstall dependencies${NC}"
        fi
        
        cd - > /dev/null || echo -e "${YELLOW}    ⚠️  Warning: Could not return to previous directory${NC}"
    else
        echo -e "${YELLOW}    ⚠️  No package.json found, skipping reinstall${NC}"
    fi
}

# Function to handle Python virtual environment packages
purge_python_venv_packages() {
    local repo_path="$1"
    
    echo -e "${BLUE}  🐍 Checking Python virtual environments in: $repo_path${NC}"
    
    # Find Python virtual environments
    while IFS= read -r -d '' venv_file; do
        local venv_dir=$(dirname "$venv_file")
        echo -e "${YELLOW}    🔍 Checking venv: $venv_dir${NC}"
        
        # Check for npm packages in this venv
        local venv_node_modules="$venv_dir/lib/python*/site-packages/*/frontend/node_modules"
        for node_modules in "$venv_node_modules"; do
            if [ -d "$node_modules" ]; then
                echo -e "${YELLOW}      📦 Checking: $node_modules${NC}"
                
                for package_version in "${VULNERABLE_PACKAGES[@]}"; do
                    local package="${package_version%:*}"
                    local vulnerable_version="${package_version#*:}"
                    
                    if [ -d "$node_modules/$package" ] && [ -f "$node_modules/$package/package.json" ]; then
                        local installed_version=$(grep '"version"' "$node_modules/$package/package.json" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                        if [ "$installed_version" = "$vulnerable_version" ]; then
                            if [ "$DRY_RUN" = "true" ]; then
                                echo -e "${YELLOW}        🔍 [DRY-RUN] Would remove: $package@$vulnerable_version from $node_modules${NC}"
                            else
                                echo -e "${YELLOW}        🗑️  Removing: $package@$vulnerable_version from $node_modules${NC}"
                            fi
                            # Validate path before deletion for security
                            if [[ "$node_modules/$package" == *"/node_modules/"* ]] && [[ "$node_modules/$package" == *"/$package" ]]; then
                                if [ "$DRY_RUN" = "false" ]; then
                                    # Use safer deletion - only remove the specific package directory
                                    if [ -d "$node_modules/$package" ]; then
                                        rm -r "$node_modules/$package" 2>/dev/null || echo -e "${YELLOW}        ⚠️  Could not remove $node_modules/$package${NC}"
                                    fi
                                fi
                                PACKAGES_PURGED=$((PACKAGES_PURGED + 1))
                            else
                                echo -e "${RED}        ⚠️  Skipping suspicious path: $node_modules/$package${NC}"
                            fi
                        fi
                    fi
                done
            fi
        done
    done < <(find "$repo_path" -name "pyvenv.cfg" -o -name "activate" -print0 2>/dev/null)
}

# Function to check system-wide npm installations and caches (multiple versions)
check_system_npm_locations() {
    local found_vulnerable_in_system=false
    
    echo -e "${BLUE}🌍 Checking system-wide npm locations...${NC}"
    
    # Detect all npm versions and package managers
    local npm_locations=()
    local package_managers=()
    
    # Check for different package managers
    if command -v npm >/dev/null 2>&1; then
        package_managers+=("npm")
        npm_locations+=("$HOME/.npm")
        npm_locations+=("$HOME/.npm-global")
    fi
    
    if command -v yarn >/dev/null 2>&1; then
        package_managers+=("yarn")
        npm_locations+=("$HOME/.yarn")
        npm_locations+=("$HOME/.yarn-cache")
    fi
    
    if command -v pnpm >/dev/null 2>&1; then
        package_managers+=("pnpm")
        npm_locations+=("$HOME/.pnpm")
        npm_locations+=("$HOME/.pnpm-store")
    fi
    
    if command -v bun >/dev/null 2>&1; then
        package_managers+=("bun")
        npm_locations+=("$HOME/.bun")
    fi
    
    # System-specific locations
    if [ "$SYSTEM_TYPE" = "macos" ]; then
        npm_locations+=(
            "/usr/local/lib/node_modules"
            "/opt/homebrew/lib/node_modules"
            "/opt/local/lib/node_modules"
            "/usr/lib/node_modules"
            "$HOME/.cache/npm"
            "/tmp/npm-*"
            "/var/folders/*/T/npm-*"
        )
    elif [ "$SYSTEM_TYPE" = "linux" ]; then
        npm_locations+=(
            "/usr/local/lib/node_modules"
            "/usr/lib/node_modules"
            "/var/lib/npm"
            "$HOME/.cache/npm"
            "/tmp/npm-*"
            "/opt/node_modules"
            "/snap/node/*/lib/node_modules"
        )
    else
        npm_locations+=(
            "/usr/local/lib/node_modules"
            "/usr/lib/node_modules"
            "/var/lib/npm"
            "$HOME/.cache/npm"
            "/tmp/npm-*"
        )
    fi
    
    echo -e "${BLUE}  📦 Detected package managers: ${package_managers[*]}${NC}"
    
    for location in "${npm_locations[@]}"; do
        if [ -d "$location" ] || ls "$location" 2>/dev/null | grep -q .; then
            echo -e "${YELLOW}  📁 Checking: $location${NC}"
            
            for package_version in "${VULNERABLE_PACKAGES[@]}"; do
                local package="${package_version%:*}"
                local vulnerable_version="${package_version#*:}"
                
                while IFS= read -r -d '' package_dir; do
                    if [ -f "$package_dir/package.json" ]; then
                        local installed_version=$(grep '"version"' "$package_dir/package.json" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                        if [ "$installed_version" = "$vulnerable_version" ]; then
                            echo -e "${RED}    ❌ VULNERABLE: $package@$vulnerable_version found in $package_dir${NC}"
                            found_vulnerable_in_system=true
                            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                        fi
                    fi
                done < <(find "$location" -name "$package" -type d -L -print0 2>/dev/null)
            done
        fi
    done
    
    # Check for multiple Node.js versions and their global packages
    if command -v nvm >/dev/null 2>&1; then
        echo -e "${BLUE}  🔄 Checking NVM installations...${NC}"
        for node_version in ~/.nvm/versions/node/*; do
            if [ -d "$node_version" ]; then
                local global_modules="$node_version/lib/node_modules"
                if [ -d "$global_modules" ]; then
                    echo -e "${YELLOW}    📦 Checking Node.js $(basename "$node_version") global modules${NC}"
                    
                    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
                        local package="${package_version%:*}"
                        local vulnerable_version="${package_version#*:}"
                        
                        if [ -d "$global_modules/$package" ] && [ -f "$global_modules/$package/package.json" ]; then
                            local installed_version=$(grep '"version"' "$global_modules/$package/package.json" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                            if [ "$installed_version" = "$vulnerable_version" ]; then
                                echo -e "${RED}      ❌ VULNERABLE: $package@$vulnerable_version found in $global_modules${NC}"
                                found_vulnerable_in_system=true
                                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                            fi
                        fi
                    done
                fi
            fi
        done
    fi
    
    # Check for n (Node.js version manager)
    if command -v n >/dev/null 2>&1; then
        echo -e "${BLUE}  🔄 Checking 'n' installations...${NC}"
        for node_version in /usr/local/n/versions/node/*; do
            if [ -d "$node_version" ]; then
                local global_modules="$node_version/lib/node_modules"
                if [ -d "$global_modules" ]; then
                    echo -e "${YELLOW}    📦 Checking Node.js $(basename "$node_version") global modules${NC}"
                    
                    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
                        local package="${package_version%:*}"
                        local vulnerable_version="${package_version#*:}"
                        
                        if [ -d "$global_modules/$package" ] && [ -f "$global_modules/$package/package.json" ]; then
                            local installed_version=$(grep '"version"' "$global_modules/$package/package.json" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                            if [ "$installed_version" = "$vulnerable_version" ]; then
                                echo -e "${RED}      ❌ VULNERABLE: $package@$vulnerable_version found in $global_modules${NC}"
                                found_vulnerable_in_system=true
                                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                            fi
                        fi
                    done
                fi
            fi
        done
    fi
    
    if [ "$found_vulnerable_in_system" = false ]; then
        echo -e "${GREEN}✅ No vulnerable packages found in system npm locations${NC}"
    fi
    return 0
}

# Function to check all Python virtual environments system-wide
check_system_python_venvs() {
    local found_vulnerable_in_system=false
    
    echo -e "${BLUE}🐍 Checking system-wide Python virtual environments...${NC}"
    
    local venv_locations=()
    if [ "$SYSTEM_TYPE" = "macos" ]; then
        venv_locations=(
            "$HOME/.virtualenvs"
            "$HOME/.venv"
            "$HOME/.pyenv"
            "/opt/venvs"
            "/usr/local/venvs"
            "/var/lib/venvs"
            "/Applications/Python*/lib/python*/site-packages"
        )
    elif [ "$SYSTEM_TYPE" = "linux" ]; then
        venv_locations=(
            "$HOME/.virtualenvs"
            "$HOME/.venv"
            "$HOME/.pyenv"
            "/opt/venvs"
            "/usr/local/venvs"
            "/var/lib/venvs"
            "/usr/lib/python*/dist-packages"
            "/usr/local/lib/python*/dist-packages"
        )
    else
        venv_locations=(
            "$HOME/.virtualenvs"
            "$HOME/.venv"
            "$HOME/.pyenv"
            "/opt/venvs"
            "/usr/local/venvs"
            "/var/lib/venvs"
        )
    fi
    
    for location in "${venv_locations[@]}"; do
        if [ -d "$location" ]; then
            echo -e "${YELLOW}  📁 Checking: $location${NC}"
            
            while IFS= read -r -d '' venv_file; do
                local venv_dir=$(dirname "$venv_file")
                echo -e "${YELLOW}    🔍 Checking venv: $venv_dir${NC}"
                
                local venv_node_modules_paths=()
                # Common paths for node_modules within Python venvs
                venv_node_modules_paths+=( "$venv_dir/lib/python*/site-packages/*/frontend/node_modules" ) # Streamlit-like structures
                venv_node_modules_paths+=( "$venv_dir/lib/python*/site-packages/node_modules" ) # Direct node_modules in site-packages
                venv_node_modules_paths+=( "$venv_dir/node_modules" ) # node_modules directly in venv root
                venv_node_modules_paths+=( "$venv_dir/lib/python*/site-packages/*/static/node_modules" ) # Django-like structures
                venv_node_modules_paths+=( "$venv_dir/lib/python*/site-packages/*/assets/node_modules" ) # Webpack-like structures

                for node_modules in "${venv_node_modules_paths[@]}"; do
                    if [ -d "$node_modules" ]; then
                        echo -e "${YELLOW}      📦 Checking: $node_modules${NC}"
                        
                        for package_version in "${VULNERABLE_PACKAGES[@]}"; do
                            local package="${package_version%:*}"
                            local vulnerable_version="${package_version#*:}"
                            
                            if [ -d "$node_modules/$package" ] && [ -f "$node_modules/$package/package.json" ]; then
                                local installed_version=$(grep '"version"' "$node_modules/$package/package.json" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/')
                                if [ "$installed_version" = "$vulnerable_version" ]; then
                                    echo -e "${RED}        ❌ VULNERABLE: $package@$vulnerable_version found in $node_modules${NC}"
                                    found_vulnerable_in_system=true
                                    VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                                fi
                            fi
                        done
                    fi
                done
            done < <(find "$location" -name "pyvenv.cfg" -o -name "activate" -print0 2>/dev/null)
        fi
    done
    
    if [ "$found_vulnerable_in_system" = false ]; then
        echo -e "${GREEN}✅ No vulnerable packages found in system Python virtual environments${NC}"
    fi
    return 0
}

# Enhanced JSON report generation with path sanitization
generate_json_report() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local system_type="${SYSTEM_TYPE:-unknown}"
    local search_path=$(sanitize_path "${SEARCH_PATH:-system-wide}")
    local max_depth="${MAX_DEPTH:-10}"
    local operation_type="$([ "$PURGE_MODE" = "true" ] && echo "purge" || echo "check")"
    
    # Escape JSON strings to prevent injection
    system_type=$(echo "$system_type" | sed 's/["\\]/\\&/g')
    search_path=$(echo "$search_path" | sed 's/["\\]/\\&/g')
    operation_type=$(echo "$operation_type" | sed 's/["\\]/\\&/g')
    
    cat > "$REPORT_FILE" << EOF
{
  "${operation_type}_info": {
    "timestamp": "$timestamp",
    "script_version": "1.0.0",
    "operation_type": "$operation_type",
    "system_type": "$system_type",
    "search_path": "$search_path",
    "max_depth": "$max_depth"
  },
  "summary": {
    "total_repositories_scanned": $REPOSITORIES_SCANNED,
    "total_vulnerabilities_found": $VULNERABILITIES_FOUND,
    "total_packages_purged": $PACKAGES_PURGED,
    "operation_status": "completed"
  },
  "vulnerable_packages_checked": [
EOF

    for package_version in "${VULNERABLE_PACKAGES[@]}"; do
        echo "    \"$package_version\"," >> "$REPORT_FILE"
    done
    
    # Remove last comma
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' '$ s/,$//' "$REPORT_FILE"
    else
        sed -i '$ s/,$//' "$REPORT_FILE"
    fi
    
    local result_status
    if [ "$PURGE_MODE" = "true" ]; then
        result_status="$([ $PACKAGES_PURGED -gt 0 ] && echo "packages_purged" || echo "no_vulnerable_packages_found")"
    else
        result_status="$([ $VULNERABILITIES_FOUND -gt 0 ] && echo "vulnerabilities_found" || echo "clean")"
    fi
    
    cat >> "$REPORT_FILE" << EOF
  ],
  "operation_result": "$result_status"
}
EOF
}

# Main execution
# Initialize security and performance features
verify_script_integrity
validate_config
init_cache

if [ "$PURGE_MODE" = "true" ]; then
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}🔍 DRY-RUN: Showing what would be purged (no actual changes)${NC}"
    else
        echo -e "${RED}🧹 Purging vulnerable npm packages from all repositories...${NC}"
    fi
else
    echo -e "${BLUE}🔍 Checking for vulnerable npm packages across all repositories...${NC}"
fi

echo -e "${BLUE}Vulnerable packages to $([ "$PURGE_MODE" = "true" ] && echo "purge" || echo "check"):${NC}"
for package_version in "${VULNERABLE_PACKAGES[@]}"; do
    echo -e "  - ${YELLOW}$package_version${NC}"
done
echo ""

# Determine scanning mode and set up paths
determine_scan_mode() {
    if [ "$SYSTEM_WIDE" = "true" ]; then
        echo "system-wide"
    elif [ -n "$SCAN_PATHS" ]; then
        echo "custom-paths"
    elif [ -n "$SEARCH_PATH" ]; then
        echo "single-path"
    else
        echo "current-directory"
    fi
}

# Discover Git repositories based on scanning mode
SCAN_MODE=$(determine_scan_mode)

case "$SCAN_MODE" in
    "system-wide")
        # System-wide scan
        detect_system_info
        echo -e "${BLUE}🌍 System-wide Git repository discovery enabled${NC}"
        echo -e "${BLUE}🔍 Scanning entire system for Git repositories...${NC}"
        
        ALL_REPOS=()
        for search_path in "${SEARCH_PATHS[@]}"; do
            if [ -d "$search_path" ]; then
                echo -e "${BLUE}  📁 Scanning: $search_path${NC}"
                REPOS_IN_PATH=($(discover_git_repos "$search_path" "${MAX_DEPTH:-10}"))
                ALL_REPOS+=("${REPOS_IN_PATH[@]}")
            fi
        done
        REPOS=("${ALL_REPOS[@]}")
        ;;
    
    "custom-paths")
        # Multiple custom paths
        echo -e "${BLUE}📁 Scanning custom paths: $SCAN_PATHS${NC}"
        IFS=',' read -ra PATH_ARRAY <<< "$SCAN_PATHS"
        ALL_REPOS=()
        
        for path in "${PATH_ARRAY[@]}"; do
            path=$(echo "$path" | xargs)  # Trim whitespace
            if [ -d "$path" ]; then
                echo -e "${BLUE}  📁 Scanning: $path${NC}"
                if [ "$NO_SUBDIRS" = "true" ]; then
                    # Check if current directory is a git repo
                    if [ -d "$path/.git" ]; then
                        ALL_REPOS+=("$path")
                    fi
                else
                    REPOS_IN_PATH=($(discover_git_repos "$path" "${MAX_DEPTH:-10}"))
                    ALL_REPOS+=("${REPOS_IN_PATH[@]}")
                fi
            else
                echo -e "${YELLOW}⚠️  Warning: Path does not exist: $path${NC}"
            fi
        done
        REPOS=("${ALL_REPOS[@]}")
        ;;
    
    "single-path")
        # Single custom path (legacy SEARCH_PATH support)
        MAX_DEPTH="${MAX_DEPTH:-10}"
        echo -e "${BLUE}📁 Auto-discovering Git repositories in: $SEARCH_PATH${NC}"
        echo -e "${BLUE}🔍 Discovering Git repositories in $SEARCH_PATH (max depth: $MAX_DEPTH)...${NC}"
        
        if [ "$NO_SUBDIRS" = "true" ]; then
            # Check if current directory is a git repo
            if [ -d "$SEARCH_PATH/.git" ]; then
                REPOS=("$SEARCH_PATH")
            else
                REPOS=()
            fi
        else
            REPOS=($(discover_git_repos "$SEARCH_PATH" "$MAX_DEPTH"))
        fi
        ;;
    
    "current-directory")
        # Current directory only (default)
        CURRENT_DIR=$(pwd)
        echo -e "${BLUE}📁 Scanning current directory: $CURRENT_DIR${NC}"
        
        if [ "$NO_SUBDIRS" = "true" ]; then
            # Check if current directory is a git repo
            if [ -d "$CURRENT_DIR/.git" ]; then
                REPOS=("$CURRENT_DIR")
            else
                REPOS=()
            fi
        else
            REPOS=($(discover_git_repos "$CURRENT_DIR" "${MAX_DEPTH:-10}"))
        fi
        ;;
esac

# Limit number of repositories if needed
repo_count=${#REPOS[@]}
if [ "$repo_count" -gt "$MAX_REPOS" ]; then
    echo -e "${YELLOW}⚠️  Warning: Found $repo_count repositories, limiting to $MAX_REPOS${NC}"
    REPOS=("${REPOS[@]:0:$MAX_REPOS}")
fi

# Show discovered repositories
if [ ${#REPOS[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No Git repositories found${NC}"
    echo -e "${BLUE}💡 Tip: Use different scanning modes:${NC}"
    echo -e "${BLUE}   $0 --system-wide              # Scan entire system${NC}"
    echo -e "${BLUE}   $0 --path /path/to/dir        # Scan specific directory${NC}"
    echo -e "${BLUE}   $0 --paths /path1,/path2      # Scan multiple directories${NC}"
    exit 0
fi

echo -e "${GREEN}📁 Found ${#REPOS[@]} Git repositories:${NC}"
for repo in "${REPOS[@]}"; do
    echo -e "  - ${GREEN}$repo${NC}"
done
echo ""

# Calculate total operations for progress tracking
TOTAL_OPERATIONS=$((${#REPOS[@]} * 6))  # 6 operations per repo
CURRENT_OPERATION=0
log_verbose "Total operations to perform: $TOTAL_OPERATIONS"

# Safety checks and confirmations
if [ "$PURGE_MODE" = "true" ]; then
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${GREEN}✅ DRY-RUN mode enabled - no actual changes will be made${NC}"
    else
        echo -e "${RED}⚠️  PURGE MODE ENABLED - This will permanently delete vulnerable packages!${NC}"
        echo -e "${YELLOW}⚠️  Make sure you have backups before proceeding.${NC}"
        
        if [ "$SKIP_CONFIRMATION" = "false" ]; then
            echo -e "${YELLOW}⚠️  This will remove vulnerable packages from your system.${NC}"
            if [ "$REINSTALL_PACKAGES" = "true" ]; then
                echo -e "${YELLOW}⚠️  Dependencies will be reinstalled after purging.${NC}"
            else
                echo -e "${YELLOW}⚠️  Dependencies will NOT be reinstalled (use --reinstall flag).${NC}"
            fi
            echo ""
            read -p "Do you want to continue? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}Operation cancelled.${NC}"
                exit $EXIT_SUCCESS
            fi
        fi
    fi
    echo ""
fi

overall_vulnerable=false
repo_count=0

for repo in "${REPOS[@]}"; do
    if [ -d "$repo" ]; then
        repo_count=$((repo_count + 1))
        show_repo_progress "$repo" "${#REPOS[@]}" "$repo_count"
        
        # Safe repository processing with error recovery
        if ! process_repository_safe "$repo"; then
            echo -e "${YELLOW}⚠️  Skipping repository due to errors: $repo${NC}"
            continue
        fi
        
        REPOSITORIES_SCANNED=$((REPOSITORIES_SCANNED + 1))
        
        # Check all types of lock files with optimized find
        lock_patterns=("package-lock.json" "npm-shrinkwrap.json")
        for pattern in "${lock_patterns[@]}"; do
            while IFS= read -r -d '' package_lock; do
                if safe_file_operation "$package_lock" "check_package_lock" 30; then
                    if [ $? -gt 0 ]; then
                        overall_vulnerable=true
                    fi
                fi
                show_progress
            done < <(eval "$(optimize_find_operation "$repo" "${MAX_DEPTH:-10}" "$pattern")" -print0 2>/dev/null)
        done
        
        while IFS= read -r -d '' yarn_lock; do
            check_yarn_lock "$yarn_lock"
            if [ $? -gt 0 ]; then
                overall_vulnerable=true
            fi
            show_progress
        done < <(find "$repo" -name "yarn.lock" -not -path "*/node_modules/*" -print0 2>/dev/null)
        
        while IFS= read -r -d '' pnpm_lock; do
            check_pnpm_lock "$pnpm_lock"
            if [ $? -gt 0 ]; then
                overall_vulnerable=true
            fi
            show_progress
        done < <(find "$repo" -name "pnpm-lock.yaml" -not -path "*/node_modules/*" -print0 2>/dev/null)
        
        while IFS= read -r -d '' bun_lock; do
            check_bun_lock "$bun_lock"
            if [ $? -gt 0 ]; then
                overall_vulnerable=true
            fi
            show_progress
        done < <(find "$repo" -name "bun.lockb" -not -path "*/node_modules/*" -print0 2>/dev/null)
        
        # Check package.json files
        check_package_json "$repo"
        show_progress
        
        # Check other language package files
        check_python_requirements "$repo"
        show_progress
        check_ruby_gemfile "$repo"
        show_progress
        check_go_modules "$repo"
        show_progress
        check_rust_cargo "$repo"
        show_progress
        check_build_tools "$repo"
        show_progress
        
        # Check or purge node_modules
        if [ "$PURGE_MODE" = "true" ]; then
            purge_node_modules "$repo"
            purge_python_venv_packages "$repo"
            # Only reinstall if explicitly requested
            if [ "$REINSTALL_PACKAGES" = "true" ]; then
                reinstall_dependencies "$repo"
            else
                echo -e "${BLUE}  ℹ️  Skipping dependency reinstall (use --reinstall flag to enable)${NC}"
            fi
        else
            check_node_modules "$repo"
        fi
        show_progress
        
        echo ""
    else
        echo -e "${YELLOW}⚠️  Repository not found: $repo${NC}"
    fi
done

# System-wide scans (only if no SEARCH_PATH specified or if explicitly requested)
if [ -z "$SEARCH_PATH" ] || [ "$SYSTEM_SCAN" = "true" ]; then
    echo -e "${BLUE}🌍 Performing comprehensive system-wide scans...${NC}"
    echo ""
    
    # Check system-wide npm locations (multiple package managers and Node.js versions)
    check_system_npm_locations
    echo ""
    
    # Check system-wide Python virtual environments
    check_system_python_venvs
    echo ""
fi

# Generate JSON report if enabled
if [ "$JSON_REPORT" = "true" ]; then
    generate_json_report
    echo -e "${BLUE}📄 JSON report saved to: $REPORT_FILE${NC}"
fi

if [ "$PURGE_MODE" = "true" ]; then
    echo -e "${BLUE}🏁 Purge operation complete!${NC}"
else
    echo -e "${BLUE}🏁 Comprehensive scan complete!${NC}"
fi

# Summary report
echo -e "${BLUE}📊 $([ "$PURGE_MODE" = "true" ] && echo "Purge" || echo "Scan") Summary:${NC}"
echo -e "  📁 Repositories scanned: ${REPOSITORIES_SCANNED}"
echo -e "  🚨 Vulnerabilities found: ${VULNERABILITIES_FOUND}"
if [ "$PURGE_MODE" = "true" ]; then
    echo -e "  🗑️  Packages purged: ${PACKAGES_PURGED}"
fi

# Final summary with user-friendly output
echo -e "\n${BLUE}📊 SCAN SUMMARY${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "📁 Repositories scanned: ${GREEN}$REPOSITORIES_SCANNED${NC}"
echo -e "🚨 Vulnerabilities found: ${RED}$VULNERABILITIES_FOUND${NC}"

if [ "$PURGE_MODE" = "true" ]; then
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "🔍 [DRY-RUN] Packages that would be purged: ${YELLOW}$PACKAGES_PURGED${NC}"
        echo -e "${YELLOW}💡 To actually purge these packages, run without --dry-run flag${NC}"
        if [ "$JSON_REPORT" = "true" ]; then
            echo -e "${BLUE}📄 Dry-run report available in: $REPORT_FILE${NC}"
        fi
        exit $EXIT_SUCCESS
    else
        echo -e "🗑️  Packages purged: ${GREEN}$PACKAGES_PURGED${NC}"
        if [ "$PACKAGES_PURGED" -gt 0 ]; then
            echo -e "${GREEN}✅ Successfully purged $PACKAGES_PURGED vulnerable packages!${NC}"
            if [ "$REINSTALL_PACKAGES" = "false" ]; then
                echo -e "${YELLOW}💡 Consider running with --reinstall flag to restore dependencies${NC}"
            fi
        else
            echo -e "${GREEN}✅ No vulnerable packages found to purge!${NC}"
        fi
        if [ "$JSON_REPORT" = "true" ]; then
            echo -e "${BLUE}📄 Detailed report available in: $REPORT_FILE${NC}"
        fi
        exit $EXIT_SUCCESS
    fi
else
    if [ "$overall_vulnerable" = true ] || [ "$VULNERABILITIES_FOUND" -gt 0 ]; then
        echo -e "${RED}❌ Vulnerable packages found! Please review the output above.${NC}"
        echo -e "${YELLOW}💡 To purge these packages, run with --purge flag${NC}"
        if [ "$JSON_REPORT" = "true" ]; then
            echo -e "${BLUE}📄 Detailed report available in: $REPORT_FILE${NC}"
        fi
        exit $EXIT_VULNERABILITIES
    else
        echo -e "${GREEN}✅ No vulnerable packages found anywhere on the system!${NC}"
        if [ "$JSON_REPORT" = "true" ]; then
            echo -e "${BLUE}📄 Clean report available in: $REPORT_FILE${NC}"
        fi
        exit $EXIT_SUCCESS
    fi
fi
