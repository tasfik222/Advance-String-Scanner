@echo off
title Dragon String Scanner v2.1 - Build
color 0C

echo.
echo ==========================================
echo   Dragon String Scanner v2.1 (FAST) - Build
echo   Developer: Tasfik Abdullah
echo ==========================================
echo.

where g++ >nul 2>&1
if %errorlevel% neq 0 goto NoCompiler

echo [*] Building StringScanner.exe...
echo.

g++ -o "StringScanner.exe" "StringScanner.cpp" ^
    -lshlwapi -lshell32 -ladvapi32 -lwinhttp ^
    -std=c++17 -O2 -static -s ^
    -Wno-deprecated-declarations

if %errorlevel% equ 0 goto BuildOK
goto BuildFailed

:NoCompiler
echo [ERROR] g++ not found!
echo Install MinGW-w64 and add to PATH.
echo Download: https://winlibs.com
pause
exit /b 1

:BuildOK
echo.
echo ==========================================
echo   BUILD SUCCESSFUL!
echo ==========================================
echo.
echo   StringScanner.exe is ready.
echo.
echo   USAGE:
echo   StringScanner.exe          -- Scans C:\
echo   StringScanner.exe D:\      -- Scans D:\
echo   StringScanner.exe C:\Games -- Scans specific folder
echo   StringScanner.exe --fast   -- Skips C:\Windows, much faster
echo   StringScanner.exe --threads 4 -- Set worker thread count
echo.
echo   Run as Administrator for best results!
echo   Report saves to Desktop automatically.
echo ==========================================
goto End

:BuildFailed
echo.
echo [FAILED] Build failed - check errors above
goto End

:End
echo.
pause
