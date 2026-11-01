# install-web-servers.ps1 — installs what install-web-servers.sh uploaded to
# C:\wactest\web, once each, then removes the archives. Each on a port of its
# own, IIS holding 80:
#   nginx 1.28   C:\nginx-1.28.0, port 8083, no service: found by its folder,
#                started by place-file-artefacts.ps1
#   Apache 2.4   C:\Apache24, port 8081, service Apache2.4, a virtual host in
#                conf\extra\wac-vhost.conf (Include), its own logs
#   Apache 2.2   Program Files (x86)\Apache Software Foundation\Apache2.2,
#                port 8082, service Apache2.2
#   MariaDB      C:\mariadb, its data in C:\mariadb\data, service MariaDB
#   PostgreSQL   C:\pgsql, its data in C:\pgsql\data, service postgresql-x64-16
# A throw-away test machine: no password worth keeping, none set.
$ErrorActionPreference = 'Stop'
$web = 'C:\wactest\web'
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Say($text) { Write-Output "   $text" }

# A program run through cmd: PowerShell, stopping on errors, takes what one
# writes on its error stream for a failure. Its exit code says.
function Run($what, $command) {
    $output = & cmd /c "$command 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "$what : exit $LASTEXITCODE : $output" }
}

if (-not (Test-Path 'C:\nginx-1.28.0\nginx.exe')) {
    [IO.Compression.ZipFile]::ExtractToDirectory("$web\nginx.zip", 'C:\')
    $conf = 'C:\nginx-1.28.0\conf\nginx.conf'
    (Get-Content $conf) -replace 'listen\s+80;', 'listen 8083;' | Set-Content -Encoding ASCII $conf
    Say 'nginx installed (port 8083)'
}

if (-not (Get-Service Apache2.4 -ErrorAction SilentlyContinue)) {
    # Apache Lounge's build needs Visual C++'s runtime: Microsoft's own, or nothing.
    $signature = Get-AuthenticodeSignature "$web\vc_redist.x64.exe"
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "vc_redist.x64.exe: signature $($signature.Status)"
    }
    $process = Start-Process "$web\vc_redist.x64.exe" -Wait -PassThru -ArgumentList '/install', '/quiet', '/norestart'
    if ($process.ExitCode -notin 0, 1638, 3010) { throw "vc_redist: $($process.ExitCode)" }
    if (Test-Path 'C:\Apache24') { Remove-Item -Recurse -Force 'C:\Apache24' }
    # The archive has a few notes beside its folder: only the folder goes to C:\.
    [IO.Compression.ZipFile]::ExtractToDirectory("$web\apache24.zip", "$web\apache24")
    Move-Item "$web\apache24\Apache24" 'C:\Apache24'
    $conf = 'C:\Apache24\conf\httpd.conf'
    $text = (Get-Content $conf) -replace '^Listen 80$', 'Listen 8081' -replace '^#?ServerName .*', 'ServerName localhost:8081'
    $text += 'Include conf/extra/wac-vhost.conf'
    $text | Set-Content -Encoding ASCII $conf
    @'
<VirtualHost *:8081>
    ServerName wac-vhost.invalid
    DocumentRoot "${SRVROOT}/wac-vhost"
    ErrorLog "logs/wac-vhost-error.log"
    CustomLog "logs/wac-vhost-access.log" combined
    <Directory "${SRVROOT}/wac-vhost">
        Require all granted
    </Directory>
</VirtualHost>
'@ | Set-Content -Encoding ASCII 'C:\Apache24\conf\extra\wac-vhost.conf'
    New-Item -ItemType Directory -Force 'C:\Apache24\wac-vhost' | Out-Null
    Run 'Apache 2.4' 'C:\Apache24\bin\httpd.exe -k install -n Apache2.4'
    Start-Service Apache2.4
    Say 'Apache 2.4 installed (port 8081)'
}

$apache22 = "${env:ProgramFiles(x86)}\Apache Software Foundation\Apache2.2"
if (-not (Test-Path "$apache22\bin\httpd.exe")) {
    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "$web\apache22.msi", '/qn', 'ALLUSERS=1',
        'SERVERADMIN=wac@wac.invalid', 'SERVERNAME=localhost', 'SERVERDOMAIN=localhost', 'SERVERPORT=8082')
    if ($process.ExitCode -ne 0) { throw "Apache 2.2: msiexec $($process.ExitCode)" }
    if ((Get-Service Apache2.2).Status -ne 'Running') { Start-Service Apache2.2 }
    Say 'Apache 2.2 installed (port 8082)'
}

if (-not (Test-Path 'C:\mariadb\bin\mariadbd.exe')) {
    [IO.Compression.ZipFile]::ExtractToDirectory("$web\mariadb.zip", 'C:\')
    Rename-Item 'C:\mariadb-11.4.5-winx64' 'C:\mariadb'
    Run 'MariaDB' 'C:\mariadb\bin\mariadb-install-db.exe --datadir=C:\mariadb\data --service=MariaDB'
    Start-Service MariaDB
    Say 'MariaDB installed'
}

if (-not (Test-Path 'C:\pgsql\bin\pg_ctl.exe')) {
    [IO.Compression.ZipFile]::ExtractToDirectory("$web\pgsql.zip", 'C:\')
    # initdb refuses to run as an administrator's token and drops it itself; the
    # service runs as Network Service (by its SID: its name depends on the
    # language of Windows), which the data folder must let in.
    New-Item -ItemType Directory -Force 'C:\pgsql\data' | Out-Null
    & icacls 'C:\pgsql\data' /grant '*S-1-5-20:(OI)(CI)F' | Out-Null
    Run 'PostgreSQL' 'C:\pgsql\bin\initdb.exe -D C:\pgsql\data -U postgres -A trust -E UTF8 --no-locale'
    & icacls 'C:\pgsql\data' /grant '*S-1-5-20:(OI)(CI)F' /T | Out-Null
    Run 'PostgreSQL' 'C:\pgsql\bin\pg_ctl.exe register -N postgresql-x64-16 -D C:\pgsql\data -S auto -w'
    Start-Service postgresql-x64-16
    Say 'PostgreSQL installed'
}

Remove-Item -Recurse -Force $web
Remove-Item -Force 'C:\wactest\install-web-servers.ps1'
foreach ($s in 'Apache2.4', 'Apache2.2', 'MariaDB', 'postgresql-x64-16') { Say ("$s : " + (Get-Service $s).Status) }
