#!/usr/bin/env bash
# install-web-servers.sh — installs in a server test VM the web servers and
# database engines other than IIS (B-035, lot 3), for the witnesses of
# place-file-artefacts.ps1: nginx, Apache 2.4 and 2.2, MariaDB, PostgreSQL.
# Idempotent: what is installed stays.
#
# WHICH VERSIONS. Those whose changes reach the collection, read in their
# changelogs: Apache 2.2 and 2.4 (error log's layout, IncludeOptional); one of
# nginx (load_module is only one more directive, logs and include unchanged),
# one of MariaDB (the zip has mariadbd.exe and mysqld.exe, the data folder is
# taken raw), one of PostgreSQL (pg_log and pg_xlog lie in the data folder,
# taken whole).
#
# The archives are fetched on the host, into tools/web-servers/ (not
# versioned), and each SHA-256 checked before anything goes into the VM.
# Apache Lounge's build needs Microsoft's Visual C++ runtime, absent from the
# server: its redistributable goes along, its signature checked in the VM.
# PostgreSQL's zip is thinned first: pgAdmin, StackBuilder, the documentation
# and the headers make up most of its 300 MiB, and no witness needs them.
#
# Usage: WAC_VM=srv2022-test ./install-web-servers.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DOM="${WAC_VM:-srv2022-test}"
QGA="python3 $HERE/lib/qga.py --dom $DOM"
VMDIR='C:\wactest'
CACHE="$HERE/tools/web-servers"

# folder|file|URL|SHA-256
ARCHIVES=(
  "nginx|nginx-1.28.0.zip|https://nginx.org/download/nginx-1.28.0.zip|db8c7a529f84c819702bd1c50926b27d961a48b4f72fc7c46b30314fc2bbfd7c"
  "apache|httpd-2.4.69-261002-Win64-VS18.zip|https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.69-261002-Win64-VS18.zip|77d715d0d9cee731e2251e7ddc2090a7a8e6d41fedef2e9827cd918593c5a652"
  "apache22|httpd-2.2.25-win32-x86-no_ssl.msi|https://archive.apache.org/dist/httpd/binaries/win32/httpd-2.2.25-win32-x86-no_ssl.msi|cee8800d2f9f15dad1e3d1e7f2d2e1b331b5a39461fe6855d63c94c8f8baef9c"
  "mariadb|mariadb-11.4.5-winx64.zip|https://archive.mariadb.org/mariadb-11.4.5/winx64-packages/mariadb-11.4.5-winx64.zip|b7c11d38657f16b837e68199d73670510aadb78f42dfa5d5fdea31a7aab342e3"
  "vcredist|vc_redist.x64.exe|https://aka.ms/vc14/vc_redist.x64.exe|843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c"
  "postgresql|postgresql-16.9-1-windows-x64-binaries.zip|https://get.enterprisedb.com/postgresql/postgresql-16.9-1-windows-x64-binaries.zip|304eb7dab70717015c4fd09986122e470d53a57a3a2b443d31e2c1d83d88db88"
)
for entry in "${ARCHIVES[@]}"; do
  IFS='|' read -r folder file url sha <<<"$entry"
  mkdir -p "$CACHE/$folder"
  [[ -f "$CACHE/$folder/$file" ]] || curl -fsSL -A 'Mozilla/5.0' -o "$CACHE/$folder/$file" "$url"
  echo "$sha  $CACHE/$folder/$file" | sha256sum -c --quiet - || { echo "SHA-256 differs: $file" >&2; exit 1; }
done

THIN="$(mktemp -d)"; trap 'rm -rf "$THIN"' EXIT
python3 -I - "$CACHE/postgresql/postgresql-16.9-1-windows-x64-binaries.zip" "$THIN/pgsql.zip" <<'PY'
import sys, zipfile
LEFT_OUT = ("pgsql/pgAdmin 4/", "pgsql/StackBuilder/", "pgsql/doc/", "pgsql/include/", "pgsql/symbols/")
with zipfile.ZipFile(sys.argv[1]) as source, zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as thin:
    for item in source.infolist():
        if not item.is_dir() and not item.filename.startswith(LEFT_OUT):
            thin.writestr(item, source.read(item))
PY

# What an interrupted run left: its archives are sent again.
$QGA run --shell "rmdir /s /q $VMDIR\\web 2>nul & mkdir $VMDIR\\web & echo." >/dev/null
$QGA write "$CACHE/nginx/nginx-1.28.0.zip" "$VMDIR\\web\\nginx.zip" >/dev/null
$QGA write "$CACHE/apache/httpd-2.4.69-261002-Win64-VS18.zip" "$VMDIR\\web\\apache24.zip" >/dev/null
$QGA write "$CACHE/vcredist/vc_redist.x64.exe" "$VMDIR\\web\\vc_redist.x64.exe" >/dev/null
$QGA write "$CACHE/apache22/httpd-2.2.25-win32-x86-no_ssl.msi" "$VMDIR\\web\\apache22.msi" >/dev/null
$QGA write "$CACHE/mariadb/mariadb-11.4.5-winx64.zip" "$VMDIR\\web\\mariadb.zip" >/dev/null
$QGA write "$THIN/pgsql.zip" "$VMDIR\\web\\pgsql.zip" >/dev/null
$QGA write "$HERE/guest/install-web-servers.ps1" "$VMDIR\\install-web-servers.ps1" >/dev/null
$QGA run --timeout 1800 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\install-web-servers.ps1"
