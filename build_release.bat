@echo off
REM Build Release Package for DLL Injector
REM This script builds, tests, and packages the release binaries

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo  DLL Injector - Release Build Script
echo ================================================================================
echo.

REM Step 1: Clean previous builds
echo [1/7] Cleaning previous builds...
cargo clean
if errorlevel 1 (
    echo ERROR: Failed to clean previous builds
    exit /b 1
)
echo    Done.
echo.

REM Step 2: Check code formatting
echo [2/7] Checking code formatting...
cargo fmt --all --check
if errorlevel 1 (
    echo ERROR: Code formatting check failed
    echo Please run: cargo fmt --all
    exit /b 1
)
echo    Done.
echo.

REM Step 3: Run Clippy
echo [3/7] Running Clippy linter...
cargo clippy --workspace -- -D warnings
if errorlevel 1 (
    echo ERROR: Clippy found issues
    echo Please fix warnings and try again
    exit /b 1
)
echo    Done.
echo.

REM Step 4: Run tests
echo [4/7] Running test suite...
cargo test --workspace
if errorlevel 1 (
    echo ERROR: Tests failed
    echo Please fix failing tests and try again
    exit /b 1
)
echo    Done.
echo.

REM Step 5: Build release binaries
echo [5/7] Building release binaries...
cargo build --workspace --release
if errorlevel 1 (
    echo ERROR: Release build failed
    exit /b 1
)
echo    Done.
echo.

REM Step 6: Create release package
echo [6/7] Creating release package...

REM Create release directory
if exist release (
    echo    Removing old release directory...
    rmdir /s /q release
)
mkdir release
mkdir release\docs
mkdir release\examples

REM Copy executables
echo    Copying executables...
copy target\release\injector.exe release\
copy target\release\injector-cli.exe release\
copy target\release\test_dll.dll release\

REM Copy documentation
echo    Copying documentation...
copy README.md release\
copy LICENSE-MIT release\
copy LICENSE-APACHE release\
copy CONTRIBUTING.md release\
copy docs\*.md release\docs\

REM Copy examples
echo    Copying examples...
xcopy /E /I injector-core\examples release\examples > nul

REM Copy assets if they exist
if exist assets\icon.ico (
    echo    Copying icon...
    copy assets\icon.ico release\
)

if exist assets\screenshots (
    if exist assets\screenshots\*.png (
        echo    Copying screenshots...
        mkdir release\screenshots
        xcopy /E /I assets\screenshots release\screenshots > nul
    )
)

REM Create version file
echo    Creating version info...
echo DLL Injector v0.1.0 > release\VERSION.txt
echo Built: %date% %time% >> release\VERSION.txt
echo. >> release\VERSION.txt
echo For more information, see README.md >> release\VERSION.txt

echo    Done.
echo.

REM Step 7: Verify release package
echo [7/7] Verifying release package...
echo    Checking files...

set MISSING_FILES=0

if not exist release\injector.exe (
    echo    ERROR: Missing injector.exe
    set MISSING_FILES=1
)

if not exist release\injector-cli.exe (
    echo    ERROR: Missing injector-cli.exe
    set MISSING_FILES=1
)

if not exist release\test_dll.dll (
    echo    ERROR: Missing test_dll.dll
    set MISSING_FILES=1
)

if not exist release\README.md (
    echo    ERROR: Missing README.md
    set MISSING_FILES=1
)

if !MISSING_FILES! equ 1 (
    echo    ERROR: Release package is incomplete
    exit /b 1
)

echo    All required files present.
echo.

REM Calculate package size
for /f "tokens=3" %%a in ('dir /s /-c release ^| findstr /C:"File(s)"') do set SIZE=%%a
echo    Package size: %SIZE% bytes
echo.

echo ================================================================================
echo  Release build completed successfully!
echo ================================================================================
echo.
echo Release package location: %CD%\release\
echo.
echo Next steps:
echo.
echo   1. Test the release binaries:
echo      - Run release\injector.exe as administrator
echo      - Test all 4 injection methods
echo      - Verify documentation is complete
echo.
echo   2. Optional: Add visual assets
echo      - Add assets\icon.ico (see assets\README.md)
echo      - Capture screenshots (see assets\README.md)
echo      - Rebuild to embed icon
echo.
echo   3. Create GitHub release:
echo      - Create git tag: git tag -a v0.1.0 -m "Release v0.1.0"
echo      - Push tag: git push origin v0.1.0
echo      - Upload release\ folder as ZIP
echo      - Include release notes from docs\phases\
echo.
echo   4. Publish (optional):
echo      - crates.io: cargo publish -p injector-core
echo      - GitHub Release: Attach release ZIP
echo.
echo ================================================================================
echo.

endlocal
