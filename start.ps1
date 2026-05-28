# VibeScan Setup & Launch Script
# Run this from PowerShell as Administrator:
# irm https://raw.githubusercontent.com/cc4480/vibescan-enterprise-build/claude/codebase-analysis-9UlbO/start.ps1 | iex

$ErrorActionPreference = "Stop"
$repo = "https://github.com/cc4480/vibescan-enterprise-build.git"
$branch = "claude/codebase-analysis-9UlbO"
$folder = "$HOME\Desktop\vibescan-enterprise-build"

Write-Host ""
Write-Host "=== VibeScan Setup ===" -ForegroundColor Cyan

# 1. Check Node
try { $nodeVer = node --version 2>&1; Write-Host "Node: $nodeVer" -ForegroundColor Green }
catch { Write-Host "ERROR: Node.js not installed. Get it from https://nodejs.org" -ForegroundColor Red; exit 1 }

# 2. Check pnpm
try { $pnpmVer = pnpm --version 2>&1; Write-Host "pnpm: $pnpmVer" -ForegroundColor Green }
catch { Write-Host "Installing pnpm..." -ForegroundColor Yellow; npm install -g pnpm }

# 3. Clone or pull
if (Test-Path $folder) {
    Write-Host "Folder exists — pulling latest..." -ForegroundColor Yellow
    Set-Location $folder
    git pull origin $branch 2>&1 | Out-Null
} else {
    Write-Host "Cloning repo to Desktop..." -ForegroundColor Yellow
    git clone --branch $branch $repo $folder
    Set-Location $folder
}

# 4. Create .env if missing
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env..." -ForegroundColor Yellow
    @"
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vibescan
STRIPE_SECRET_KEY=sk_test_placeholder
STRIPE_WEBHOOK_SECRET=whsec_placeholder
DEEPSEEK_API_KEY=sk_placeholder
APP_ORIGIN=http://localhost:3000
DISABLE_PAYMENTS=true
NODE_ENV=development
"@ | Out-File -Encoding utf8 ".env"
    Write-Host ""
    Write-Host "IMPORTANT: Edit .env and set DATABASE_URL to match your Postgres password." -ForegroundColor Yellow
    Write-Host "Default assumes: user=postgres, password=postgres, db=vibescan" -ForegroundColor Yellow
    Write-Host ""
}

# 5. Install deps
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pnpm install

# 6. Build API
Write-Host "Building API server..." -ForegroundColor Yellow
pnpm --filter @workspace/api-server run build

# 7. Launch both servers in separate windows
Write-Host ""
Write-Host "=== Launching servers ===" -ForegroundColor Cyan

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$folder'; Write-Host 'API Server' -ForegroundColor Cyan; `$env:PORT='8080'; `$env:NODE_ENV='development'; node --env-file-if-exists=.env --enable-source-maps artifacts/api-server/dist/index.mjs"

Start-Sleep 3

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$folder'; Write-Host 'Frontend Dev Server' -ForegroundColor Magenta; `$env:PORT='3000'; `$env:BASE_PATH='/'; pnpm --filter @workspace/vibescan dev"

Write-Host ""
Write-Host "=== Done! ===" -ForegroundColor Green
Write-Host "Two windows are opening — wait for both to show 'ready', then open:" -ForegroundColor Green
Write-Host "  http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Start-Sleep 5
Start-Process "microsoft-edge:http://localhost:3000"
