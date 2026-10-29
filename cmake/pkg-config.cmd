@echo off
rem Picotls requires pkg-config before it looks for optional libraries such as brotli.
rem This reports a version so CMake's FindPkgConfig succeeds, and reports every module missing.
set "arg=%~1"
if /I "%arg%"=="--version" (
  echo 0.29.2
  exit /b 0
)
if /I "%arg%"=="--help" (
  echo pkg-config stub for the Windows build
  exit /b 0
)
exit /b 1
