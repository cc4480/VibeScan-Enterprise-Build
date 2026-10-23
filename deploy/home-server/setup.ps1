# Prepares this machine to run every app in docker-compose.yml.
#
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
#
# Safe to run again: it clones only what is missing, updates what is there, and
# never overwrites a .env or env\*.env you have already filled in.
#
# Written for Windows PowerShell 5.1 (built into Windows) and PowerShell 7.

$ErrorActionPreference = 'Stop'

$here    = $PSScriptRoot
$repoTop = (Resolve-Path (Join-Path $here '..\..')).Path
$appsDir = (Resolve-Path (Join-Path $repoTop '..')).Path

$repos = @('VibeScan-Enterprise-Build', 'secscan-info', 'seclayer.io2026', 'complyscan', 'SEO-scan-Pro')

function Require-Command($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "$name was not found. $hint"
    }
}

function New-Secret {
    # 24 random bytes as hex: letters and digits only, so it is safe inside a
    # connection URL without escaping.
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-Quietly([scriptblock]$command) {
    # Runs a program with all its output discarded and returns its exit code.
    # Windows PowerShell 5.1 turns a redirected stderr line into a terminating
    # error when $ErrorActionPreference is Stop, so relax it for the call: docker
    # prints harmless warnings to stderr even when it succeeds.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $command *> $null; return $LASTEXITCODE } finally { $ErrorActionPreference = $previous }
}

function Write-LfFile($path, [string[]]$lines) {
    # LF line endings and no byte-order mark, which Docker reads reliably.
    $text = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

Require-Command git    'Install Git for Windows from https://git-scm.com/download/win and run this again.'
Require-Command docker 'Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and run this again.'

if ((Test-Quietly { docker info }) -ne 0) {
    throw 'Docker is installed but not running. Start Docker Desktop, wait until it says "Engine running", and run this again.'
}

Write-Host "Apps folder: $appsDir"

# 1. The five repositories, side by side. core.autocrlf=false keeps the shell
#    scripts the images run with Unix line endings; with Windows line endings
#    they fail inside the containers with "\r: not found".
foreach ($repo in $repos) {
    $path = Join-Path $appsDir $repo
    if (Test-Path (Join-Path $path '.git')) {
        Write-Host "Updating $repo"
        git -C $path pull --ff-only
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not update $repo (local changes?). Leaving it as it is." }
    } else {
        Write-Host "Cloning $repo"
        git clone -c core.autocrlf=false "https://github.com/cc4480/$repo.git" $path
        if ($LASTEXITCODE -ne 0) { throw "Could not clone $repo. If it is private, sign in to GitHub when Git asks." }
    }
}

# 2. .env with generated database passwords.
$envFile = Join-Path $here '.env'
if (-not (Test-Path $envFile)) {
    $lines = Get-Content (Join-Path $here '.env.example')
    $secretKeys = @('POSTGRES_PASSWORD', 'SECSCAN_DB_PASSWORD', 'SECLAYER_DB_PASSWORD', 'COMPLYSCAN_DB_PASSWORD', 'SEOSCAN_DB_PASSWORD')
    $lines = $lines | ForEach-Object {
        $line = $_
        foreach ($key in $secretKeys) {
            if ($line -match "^$key=\s*$") { $line = "$key=$(New-Secret)" }
        }
        $line
    }
    Write-LfFile $envFile $lines
    Write-Host 'Created .env with new database passwords.'
} else {
    Write-Host '.env already exists; left unchanged.'
}

# 3. One settings file per app, from its template.
foreach ($name in @('secscan', 'seclayer', 'complyscan', 'seoscan')) {
    $target = Join-Path $here "env\$name.env"
    if (-not (Test-Path $target)) {
        Write-LfFile $target (Get-Content (Join-Path $here "env\$name.env.example"))
        Write-Host "Created env\$name.env (fill it in from Railway)."
    }
}

# 4. Folders the stack writes to.
foreach ($dir in @('backups', 'migration')) {
    $p = Join-Path $here $dir
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

Write-Host ''
Write-Host 'Next (README.md has the details):'
Write-Host '  1. Fill in env\secscan.env, env\seclayer.env, env\complyscan.env, env\seoscan.env from Railway.'
Write-Host '  2. Copy each database:  powershell -ExecutionPolicy Bypass -File .\migrate-db.ps1 -App secscan   (and seclayer, complyscan, seoscan)'
Write-Host '  3. Start everything:    docker compose up -d --build'
