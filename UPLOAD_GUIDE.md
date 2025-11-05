# 🚀 Quick Upload Guide

## Step-by-Step Instructions

### Step 1: Take Screenshots
1. Start your Flask application:
   ```powershell
   python app.py
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Take screenshots of these pages:
   - **homepage.png**: Main landing page
   - **encryption.png**: Encryption page
   - **dashboard.png**: User dashboard (after login)
   - **vault.png**: File vault page
   - **profile.png**: Profile page
   - **admin_dashboard.png**: Admin dashboard (if you have admin access)

4. Save all screenshots in the `screenshots/` folder

### Step 2: Upload to GitHub

**Option A: Use the automated script (Easy)**
```powershell
.\update_github.bat
```
Just double-click `update_github.bat` or run it from PowerShell.

**Option B: Use PowerShell script (Interactive)**
```powershell
.\update_github.ps1
```

**Option C: Manual commands**
```powershell
# Add all changes
git add .

# Commit with message
git commit -m "Add screenshots and update README"

# Push to GitHub
git push origin main
```

### Step 3: Verify on GitHub
Visit https://github.com/kaone31056789/CipherSphere to see your updated repository!

## Troubleshooting

### Screenshots not showing on GitHub?
- Make sure files are named exactly as specified (lowercase)
- Use `.png` format
- Check that files are in the `screenshots/` folder
- Wait a few minutes for GitHub to process images

### Git push errors?
```powershell
# Pull latest changes first
git pull origin main

# Then try pushing again
git push origin main
```

### Need to update screenshots later?
1. Replace the old screenshot files
2. Run the update script again
3. GitHub will automatically update the images

## Screenshot Checklist

- [ ] homepage.png
- [ ] encryption.png
- [ ] dashboard.png
- [ ] vault.png
- [ ] profile.png
- [ ] admin_dashboard.png
- [ ] All files are PNG format
- [ ] Files are in screenshots/ folder
- [ ] Pushed to GitHub
- [ ] Verified on GitHub page

---

**Need help?** Check `screenshots/README.md` for detailed screenshot tips!
