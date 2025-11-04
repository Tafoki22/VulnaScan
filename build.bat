@echo off
echo 🚀 Building VulnaScan.exe...

:: Activate virtual environment
call venv\Scripts\activate

:: Install PyInstaller silently
pip install pyinstaller -q

:: Create dist directory if missing (optional)
if not exist dist mkdir dist

:: Build the executable
pyinstaller ^
  --noconfirm ^
  --onefile ^
  --windowed ^
  --name "VulnaScan" ^
  --add-data "vulnscan;vulnscan" ^
  --hidden-import vulnscan.core ^
  --hidden-import vulnscan.gui ^
  run.py

:: Completion message
echo.
echo ✅ Build complete!
echo 📁 Your app is ready: dist\VulnaScan.exe
echo.
pause