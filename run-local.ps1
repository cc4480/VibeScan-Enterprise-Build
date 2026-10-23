# run-local.ps1 — start the SecScan stack locally on Windows.
# Usage:  powershell -ExecutionPolicy Bypass -File .\run-local.ps1
# Opens two new windows: the API server (port 8080) and the Vite frontend (port 18425).
# App entry point:  http://localhost:18425
#
# Prereqs handled elsewhere: `pnpm install`, shared-lib builds, `db:push`, and the
# Postgres container. This script only (re)starts the two app servers.

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot

# Git's bin provides `sh`, needed by some pnpm lifecycle scripts.
$env:PATH = "C:\Program Files\Git\bin;$env:PATH"

# Ensure the Postgres container is running.
$pg = docker ps --filter "name=vibescan-pg" --format "{{.Names}}"
if (-not $pg) {
  Write-Host "Starting Postgres container vibescan-pg..." -ForegroundColor Cyan
  docker start vibescan-pg | Out-Null
}

# Load .env into this process so child servers inherit the vars.
Get-Content (Join-Path $repo ".env") |
  Where-Object { $_ -match '=' -and $_ -notmatch '^\s*#' } |
  ForEach-Object { $k,$v = $_ -split '=',2; Set-Item -Path "Env:$($k.Trim())" -Value $v.Trim() }

# API server (Express + pg-boss) on port 8080.
$apiDir = Join-Path $repo "artifacts\api-server"
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "`$env:PATH='C:\Program Files\Git\bin;'+`$env:PATH; Set-Location '$apiDir'; " +
  "node --enable-source-maps --env-file='$repo\.env' .\dist\index.mjs"
)

# Frontend (Vite) on port 18425.
$feDir = Join-Path $repo "artifacts\vibescan"
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "`$env:PATH='C:\Program Files\Git\bin;'+`$env:PATH; `$env:PORT='18425'; Set-Location '$feDir'; " +
  "pnpm exec vite --config vite.config.ts --host 0.0.0.0"
)

Write-Host ""
Write-Host "Started. Open the app at:  http://localhost:18425" -ForegroundColor Green
Write-Host "API health check:          http://localhost:8080/api/healthz" -ForegroundColor Green
Write-Host "(Vite's first cold start can take ~2 min on this machine.)" -ForegroundColor DarkGray
