# CipherSphere GitHub Update Script
# This script will add screenshots and push changes to GitHub

Write-Host "🔒 CipherSphere - GitHub Update Script" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
$currentDir = Get-Location
Write-Host "📁 Current directory: $currentDir" -ForegroundColor Yellow

# Check if screenshots exist
$screenshotsPath = Join-Path $currentDir "screenshots"
$screenshotFiles = Get-ChildItem -Path $screenshotsPath -Filter "*.png" -ErrorAction SilentlyContinue

if ($screenshotFiles.Count -eq 0) {
    Write-Host "⚠️  No screenshots found in the screenshots folder!" -ForegroundColor Red
    Write-Host "Please add your screenshots first, then run this script again." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Expected screenshots:" -ForegroundColor Cyan
    Write-Host "  - homepage.png"
    Write-Host "  - encryption.png"
    Write-Host "  - dashboard.png"
    Write-Host "  - vault.png"
    Write-Host "  - profile.png"
    Write-Host "  - admin_dashboard.png"
    Write-Host ""
    exit
}

Write-Host "✅ Found $($screenshotFiles.Count) screenshot(s):" -ForegroundColor Green
foreach ($file in $screenshotFiles) {
    $size = [math]::Round($file.Length / 1KB, 2)
    Write-Host "   - $($file.Name) ($size KB)" -ForegroundColor White
}
Write-Host ""

# Check git status
Write-Host "📊 Checking git status..." -ForegroundColor Yellow
git status

Write-Host ""
Write-Host "Would you like to:" -ForegroundColor Cyan
Write-Host "1. Add and commit screenshots only"
Write-Host "2. Add and commit all changes (screenshots + README)"
Write-Host "3. Cancel"
Write-Host ""

$choice = Read-Host "Enter your choice (1-3)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "📤 Adding screenshots..." -ForegroundColor Yellow
        git add screenshots/
        
        Write-Host "💾 Committing changes..." -ForegroundColor Yellow
        git commit -m "Add application screenshots"
        
        Write-Host "🚀 Pushing to GitHub..." -ForegroundColor Yellow
        git push origin main
        
        Write-Host ""
        Write-Host "✅ Screenshots uploaded successfully!" -ForegroundColor Green
    }
    "2" {
        Write-Host ""
        Write-Host "📤 Adding all changes..." -ForegroundColor Yellow
        git add .
        
        Write-Host "💾 Committing changes..." -ForegroundColor Yellow
        $commitMessage = Read-Host "Enter commit message (or press Enter for default)"
        if ([string]::IsNullOrWhiteSpace($commitMessage)) {
            $commitMessage = "Update documentation and add screenshots"
        }
        git commit -m $commitMessage
        
        Write-Host "🚀 Pushing to GitHub..." -ForegroundColor Yellow
        git push origin main
        
        Write-Host ""
        Write-Host "✅ All changes uploaded successfully!" -ForegroundColor Green
    }
    "3" {
        Write-Host ""
        Write-Host "❌ Operation cancelled." -ForegroundColor Red
        exit
    }
    default {
        Write-Host ""
        Write-Host "❌ Invalid choice. Operation cancelled." -ForegroundColor Red
        exit
    }
}

Write-Host ""
Write-Host "🌐 View your repository at:" -ForegroundColor Cyan
Write-Host "   https://github.com/kaone31056789/CipherSphere" -ForegroundColor White
Write-Host ""
Write-Host "✨ Done!" -ForegroundColor Green
