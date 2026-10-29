@echo off
setlocal EnableExtensions

if defined ANDROID_NDK_HOME set "NDK_ROOT=%ANDROID_NDK_HOME%"
if not defined NDK_ROOT if defined ANDROID_NDK_ROOT set "NDK_ROOT=%ANDROID_NDK_ROOT%"
if not defined NDK_ROOT if defined ANDROID_HOME set "SDK_ROOT=%ANDROID_HOME%"
if not defined NDK_ROOT if defined ANDROID_SDK_ROOT set "SDK_ROOT=%ANDROID_SDK_ROOT%"
if not defined NDK_ROOT if not defined SDK_ROOT set "SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
if not defined NDK_ROOT if exist "%SDK_ROOT%\ndk" (
  for /f "delims=" %%D in ('dir /b /ad "%SDK_ROOT%\ndk" ^| sort') do set "NDK_ROOT=%SDK_ROOT%\ndk\%%D"
)

if not defined NDK_ROOT (
  echo Android NDK not found. Set ANDROID_NDK_HOME. 1>&2
  exit /b 1
)

set "CC=%NDK_ROOT%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
if not exist "%CC%" (
  echo NDK compiler not found: %CC% 1>&2
  exit /b 1
)

"%CC%" @native-build.rsp
exit /b %ERRORLEVEL%
