@echo off
echo.
echo ================================================
echo  CipherSphere - Quick GitHub Update
echo ================================================
echo.

REM Check for screenshots
if not exist "screenshots\*.png" (
    echo [ERROR] No screenshots found!
    echo.
    echo Please add screenshots to the 'screenshots' folder first.
    echo Expected files: homepage.png, encryption.png, dashboard.png, vault.png, profile.png, admin_dashboard.png
    echo.
    pause
    exit /b
)

echo [INFO] Screenshots found. Preparing to upload...
echo.

REM Show git status
git status

echo.
echo ================================================
echo.
echo Press any key to continue with git push...
echo (or Ctrl+C to cancel)
pause > nul

echo.
echo [STEP 1] Adding changes to git...
git add .

echo.
echo [STEP 2] Committing changes...
git commit -m "Update documentation and add application screenshots"

echo.
echo [STEP 3] Pushing to GitHub...
git push origin main

echo.
echo ================================================
echo  SUCCESS! Changes uploaded to GitHub
echo ================================================
echo.
echo View at: https://github.com/kaone31056789/CipherSphere
echo.
pause
