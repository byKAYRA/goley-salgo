$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Starting Goley Server Emulator (Auth: 8000, Entry: 2270, Lobby: 2271)..."
cargo run -p server --release
