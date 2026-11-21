@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
if not exist "%~dp0src\server\server.mjs" (
  echo [Wiretok] Dosyalar eksik gorunuyor.
  echo Lutfen ZIP arsivini once bir klasore cikarin, sonra tekrar calistirin.
  pause
  exit /b 1
)
set "NODE_BIN="
for /f "delims=" %%p in ('where node 2^>nul') do if not defined NODE_BIN set "NODE_BIN=%%p"
if not defined NODE_BIN if exist "C:\Program Files\nodejs\node.exe" set "NODE_BIN=C:\Program Files\nodejs\node.exe"
if not defined NODE_BIN if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "NODE_BIN=%LOCALAPPDATA%\Programs\nodejs\node.exe"
if defined NODE_BIN (
  set "NODE_MAJOR=0"
  for /f "usebackq tokens=1 delims=v." %%v in (`"!NODE_BIN!" -v 2^>nul`) do set "NODE_MAJOR=%%v"
  if !NODE_MAJOR! LSS 22 set "NODE_BIN="
)
if not defined NODE_BIN if exist "%APPDATA%\Antigravity\bin\agy-node.cmd" set "NODE_BIN=%APPDATA%\Antigravity\bin\agy-node.cmd"
if not defined NODE_BIN (
  echo [Wiretok] Node.js 22+ bulunamadi.
  echo Lutfen https://nodejs.org adresinden Node.js 22+ LTS kurun ve tekrar deneyin.
  pause
  exit /b 1
)
call "!NODE_BIN!" --no-warnings "%~dp0bin\launch.mjs" %*
if errorlevel 1 (
  echo.
  echo [Wiretok] Baslatilamadi. Yukaridaki hata mesajini kontrol edin.
  pause
  exit /b 1
)
exit /b 0
