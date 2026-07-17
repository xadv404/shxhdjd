@echo off
setlocal
cd /d "%~dp0"

where go >nul 2>&1
if errorlevel 1 (
  echo Go n'est pas installe ou pas dans le PATH.
  echo Installe Go: https://go.dev/dl/
  echo.
  pause
  exit /b 1
)

echo Building grabber.exe ...
go build -ldflags="-s -w" -o grabber.exe ./cmd/grabber
if errorlevel 1 (
  echo.
  echo Build failed.
  echo.
  pause
  exit /b 1
)

echo.
echo OK - lance avec: grabber.exe
echo.
pause
exit /b 0
