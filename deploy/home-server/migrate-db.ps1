# Copies one app's database from Railway into the home database.
#
#   powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App secscan
#
# -App is one of: secscan, seclayer, complyscan, seoscan.
# It asks for that app's Railway public database URL (typed input is hidden),
# and refuses to overwrite a home database that already has tables unless you
# add -Force (which empties it first).
#
# Run it BEFORE the app's first start at home, or with -Force afterwards: the
# app is stopped while its data is copied. The dump is kept in .\migration as
# a second copy.
#
# Written for Windows PowerShell 5.1 (built into Windows) and PowerShell 7.
# 5.1 does not escape double quotes inside arguments passed to programs, so no
# argument below contains one: SQL that needs quoting is sent on stdin.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('secscan', 'seclayer', 'complyscan', 'seoscan')]
    [string]$App,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$image    = 'postgres:17'
$network  = 'homeserver_default'
$services = @{
    secscan    = @('secscan-web', 'secscan-worker')
    seclayer   = @('seclayer')
    complyscan = @('complyscan')
    seoscan    = @('seoscan')
}[$App]
$countTables = "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind in ('r','p') and n.nspname not in ('pg_catalog','information_schema')"

function Get-EnvValue($key) {
    $line = Get-Content '.env' | Where-Object { $_ -match "^$key=" } | Select-Object -First 1
    if (-not $line) { throw "$key is missing from .env. Run setup.ps1 first." }
    return ($line -replace "^$key=", '').Trim()
}

function Test-Quietly([scriptblock]$command) {
    # Runs a program with all output discarded and returns its exit code.
    # Windows PowerShell 5.1 turns redirected stderr into a terminating error
    # under 'Stop', so relax it for the call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $command *> $null; return $LASTEXITCODE } finally { $ErrorActionPreference = $previous }
}

function Invoke-Checked([string]$what, [scriptblock]$command) {
    # Runs a program, returns its stdout, and stops with a clear message if it
    # fails. stderr stays on screen (not redirected), which 5.1 tolerates.
    $output = & $command
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE). See the messages above." }
    return $output
}

$postgresPassword = Get-EnvValue 'POSTGRES_PASSWORD'
if (-not (Test-Path '.\migration')) { New-Item -ItemType Directory -Path '.\migration' | Out-Null }
$migrationDir = (Resolve-Path '.\migration').Path

# 1. Home database up, this app stopped.
Write-Host 'Starting the home database...'
Invoke-Checked 'Starting the database' { docker compose up -d db } | Out-Null
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    if ((Test-Quietly { docker compose exec -T db pg_isready -U postgres }) -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ready) { throw 'The home database did not become ready. Check: docker compose logs db' }
Test-Quietly { docker compose stop @services } | Out-Null

# 2. The Railway database's address. Asked for with Read-Host -AsSecureString,
#    which keeps it off the screen and out of PowerShell's history. For a
#    scripted run, set RAILWAY_DATABASE_URL instead and nothing is asked.
$railwayUrl = $env:RAILWAY_DATABASE_URL
if (-not $railwayUrl) {
    Write-Host ''
    Write-Host "Railway: open the Postgres service used by $App -> Variables, and copy DATABASE_PUBLIC_URL."
    Write-Host "(Two Postgres services in the project? The app's DATABASE_URL in its Raw Editor names the one it uses.)"
    $secure = Read-Host -AsSecureString 'Paste it here (input is hidden)'
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $railwayUrl = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
$railwayUrl = $railwayUrl.Trim()
if ($railwayUrl -notmatch '^postgres(ql)?://[^\s"]+$') { throw 'That does not look like a database URL (it should start with postgresql:// and contain no spaces).' }

# 3. Version check: this stack runs PostgreSQL 17, and pg_dump 17 cannot read a
#    newer server.
$versionNum = Invoke-Checked 'Connecting to Railway' { docker run --rm $image psql $railwayUrl -Atc 'show server_version_num' }
$versionNum = [int]("$versionNum".Trim())
Write-Host "Railway database version: $([math]::Floor($versionNum / 10000))"
if ($versionNum -ge 180000) {
    throw 'Railway runs PostgreSQL 18 or newer; this setup uses 17. Stop here and ask for the compose file to be moved to 18 first.'
}

# 4. Refuse to mix into a database that already has data, unless -Force.
$tableCount = Invoke-Checked 'Checking the home database' { docker compose exec -T db psql -U postgres -d $App -Atc $countTables }
if ([int]("$tableCount".Trim()) -gt 0) {
    if (-not $Force) {
        throw "The home '$App' database already has tables (the app has probably started once). Run again with -Force to replace them with Railway's data."
    }
    Write-Host "Emptying the home '$App' database (-Force)..."
    $recreate = @"
DROP DATABASE IF EXISTS "$App" WITH (FORCE);
CREATE DATABASE "$App" OWNER "$App";
REVOKE ALL ON DATABASE "$App" FROM PUBLIC;
"@
    Invoke-Checked 'Recreating the database' { $recreate | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1 } | Out-Null
}

# 5. Extensions need a superuser to create, so create them first; the restore
#    below runs as the app's own role and then only finds them already there.
$extensions = Invoke-Checked 'Listing Railway extensions' {
    docker run --rm $image psql $railwayUrl -Atc "select extname from pg_extension where extname <> 'plpgsql'"
}
foreach ($ext in @($extensions | Where-Object { $_ -and "$_".Trim() })) {
    $ext = "$ext".Trim()
    if ($ext -notmatch '^[a-z0-9_\-]+$') { throw "Unexpected extension name: $ext" }
    Write-Host "Creating extension $ext"
    $sql = "CREATE EXTENSION IF NOT EXISTS `"$ext`";"
    Invoke-Checked "Creating extension $ext" { $sql | docker compose exec -T db psql -U postgres -d $App -v ON_ERROR_STOP=1 } | Out-Null
}

# 6. Dump from Railway (custom format, no Railway owners or grants).
$dumpName = "$App-$(Get-Date -Format 'yyyyMMdd-HHmmss').dump"
Write-Host "Copying from Railway into migration\$dumpName ..."
Invoke-Checked 'Dumping from Railway' {
    docker run --rm -v "${migrationDir}:/migration" $image pg_dump $railwayUrl -Fc --no-owner --no-acl -f "/migration/$dumpName"
} | Out-Null

# 7. Restore into the home database, every object owned by the app's role.
Write-Host "Loading it into the home '$App' database..."
docker run --rm --network $network -e "PGPASSWORD=$postgresPassword" -v "${migrationDir}:/migration" $image pg_restore -h db -U postgres -d $App --no-owner --no-acl "--role=$App" "/migration/$dumpName"
$restoreExit = $LASTEXITCODE

$after = Invoke-Checked 'Counting tables' { docker compose exec -T db psql -U postgres -d $App -Atc $countTables }
Write-Host ''
Write-Host "Home '$App' database now has $("$after".Trim()) tables."
if ($restoreExit -ne 0) {
    Write-Warning ("pg_restore reported errors (listed above). Messages about extensions ('must be owner of extension') are expected and harmless. " +
        'Anything about a table, sequence or index is not: keep Railway running and ask for help with the messages.')
}
Write-Host "Start the app with:  docker compose up -d --build $($services -join ' ')"
