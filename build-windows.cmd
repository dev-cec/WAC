@echo off
rem build-windows.cmd - builds WAC.exe on Windows by the one build procedure,
rem build-windows.sh, run in the bash of Git for Windows (needed anyway to
rem clone the repository), with MinGW-Builds' compiler first in the PATH.
rem   MinGW-Builds: x86_64-13.2.0-release-win32-seh-msvcrt-rt_v11-rev1, unpacked
rem   into C:\mingw-win32, or into the folder WAC_MINGW names. Its win32 threads
rem   and msvcrt give the imports of the Linux build: a posix gcc adds 38 of them
rem   (doc\BUILD_EN.md, B-024).
rem Usage: build-windows.cmd [--clean] [--test]
setlocal
if not defined WAC_MINGW set "WAC_MINGW=C:\mingw-win32\mingw64"
if not exist "%WAC_MINGW%\bin\g++.exe" (
  echo MinGW-Builds not found in %WAC_MINGW%: see doc\BUILD_EN.md
  exit /b 1
)
set "GIT_BASH=%ProgramFiles%\Git\bin\bash.exe"
if not exist "%GIT_BASH%" (
  echo Git for Windows not found: %GIT_BASH%
  exit /b 1
)
set "PATH=%WAC_MINGW%\bin;%PATH%"
"%GIT_BASH%" "%~dp0build-windows.sh" %*
exit /b %ERRORLEVEL%
