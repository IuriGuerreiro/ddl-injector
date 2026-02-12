# Launch the DLL Injector UI with automatic UAC elevation
# This ensures the manifest is properly read and UAC prompt appears

$injectorPath = Join-Path $PSScriptRoot "target\release\injector.exe"

if (-not (Test-Path $injectorPath)) {
    Write-Host "❌ Injector not found at: $injectorPath" -ForegroundColor Red
    Write-Host "   Please build it first: cargo build --release" -ForegroundColor Yellow
    exit 1
}

Write-Host "🚀 Launching DLL Injector..." -ForegroundColor Cyan
Write-Host "   Path: $injectorPath" -ForegroundColor Gray

# Launch with Start-Process to ensure manifest is read
# This will trigger the UAC prompt properly
Start-Process -FilePath $injectorPath

Write-Host "✓ Launched! UAC prompt should appear." -ForegroundColor Green
