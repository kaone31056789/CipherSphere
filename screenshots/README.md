# 📸 CipherSphere Screenshots Guide

## How to Take Screenshots

### Recommended Pages to Capture:

1. **homepage.png** - Landing page (index.html)
   - URL: `http://localhost:5000/`
   - Capture the full hero section with animations

2. **encryption.png** - Encryption interface
   - URL: `http://localhost:5000/encrypt`
   - Show the encryption form with algorithm selection

3. **dashboard.png** - User dashboard
   - URL: `http://localhost:5000/dashboard`
   - Display user stats and recent activity

4. **vault.png** - File vault
   - URL: `http://localhost:5000/vault`
   - Show the file list with encryption details

5. **profile.png** - Profile management
   - URL: `http://localhost:5000/profile`
   - Display user profile with settings

6. **admin_dashboard.png** - Admin dashboard
   - URL: `http://localhost:5000/admin`
   - Show admin statistics and controls

## Screenshot Tips:

### For Windows (using Snipping Tool or Snip & Sketch):
1. Press `Win + Shift + S` to open Snipping Tool
2. Select the area you want to capture
3. The screenshot will be copied to clipboard
4. Open Paint or any image editor
5. Paste (Ctrl + V) and save as PNG

### For Best Quality:
- Use 1920x1080 resolution for consistency
- Capture at full width when possible
- Ensure good contrast and visibility
- Remove any sensitive test data before capturing
- Take screenshots in dark mode for the cyberpunk theme

### Using Browser DevTools:
1. Press F12 to open DevTools
2. Press Ctrl+Shift+M to toggle device toolbar
3. Select "Responsive" and set custom dimensions
4. Take screenshot using browser's built-in tool

## After Taking Screenshots:

1. Save all screenshots in this `screenshots/` folder
2. Name them exactly as listed above (lowercase, use underscores)
3. Verify all images are PNG format
4. Ensure file sizes are reasonable (< 1MB each)

## Uploading to GitHub:

```powershell
# Navigate to project directory
cd "c:\Users\parik\OneDrive\Documents\Parikshit Colledge\python project"

# Add screenshots to git
git add screenshots/*.png

# Commit the changes
git commit -m "Add application screenshots"

# Push to GitHub
git push origin main
```
