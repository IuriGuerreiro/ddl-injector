# Assets Directory

This directory contains visual assets for the DLL Injector project.

## Icon (Pending)

**File:** `icon.ico`
**Status:** ⚠️ **Not yet added**

### Requirements:
- Format: ICO with multiple sizes (16x16, 32x32, 48x48, 256x256)
- Theme: Injection, debugging, or development related
- License: Free to use with attribution, or custom-created

### Recommended Sources:
1. **Icons8** (https://icons8.com/) - Free with attribution
   - Search for: "syringe", "injection", "debugging", "tools"
   - Download as ICO with multiple sizes
   - Add attribution to README acknowledgments

2. **Flaticon** (https://www.flaticon.com/) - Free with attribution
   - Similar search terms
   - Ensure license allows project use

3. **Custom Creation:**
   - Create PNG in design tool (GIMP, Photoshop, Figma)
   - Convert to ICO using online converter or ImageMagick
   - Recommended size: 256x256 PNG, then convert to multi-size ICO

### Integration:
Once icon.ico is added:
1. Place in `assets/icon.ico`
2. Update `injector-ui/injector.rc` to reference it (already done)
3. Rebuild project - icon will embed in injector.exe

## Screenshots (Pending)

**Directory:** `screenshots/`
**Status:** ⚠️ **Not yet added**

### Required Screenshots:

1. **main_window.png**
   - Full application window
   - Process list visible with notepad.exe selected
   - DLL path filled in
   - Clean, professional appearance

2. **injection_success.png**
   - Successful injection shown in logs
   - MessageBox visible from test_dll.dll
   - Demonstrates working functionality

3. **method_selection.png** (optional)
   - Injection method dropdown expanded
   - Shows all 4 available methods

### How to Capture:

1. **Prepare Environment:**
   ```bash
   # Build release version
   cargo build --workspace --release

   # Start test target
   start notepad.exe

   # Run injector as admin
   # Right-click injector.exe → Run as administrator
   ```

2. **Capture Screenshots:**
   - Use Windows Snipping Tool (Win+Shift+S)
   - Or use ShareX for better quality
   - Save as PNG format
   - Optimize images (use TinyPNG or similar)

3. **Placement:**
   - Save screenshots to `assets/screenshots/`
   - Reference in README.md

### Usage in README:

Once screenshots are captured, add to README.md:

```markdown
## Screenshots

![Main Window](assets/screenshots/main_window.png)
*DLL Injector main interface*

![Successful Injection](assets/screenshots/injection_success.png)
*Successful DLL injection into notepad.exe*
```

## Notes

- Assets are optional but enhance professionalism
- Icon shows in Windows Explorer and taskbar
- Screenshots help users understand UI before trying
- Both can be added after release if needed

**Priority:** Low - Project is fully functional without these assets.
