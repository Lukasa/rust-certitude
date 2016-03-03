REM For the license on this file, please see NOTICES
echo on
SetLocal EnableDelayedExpansion

REM This is the recommended way to choose the toolchain version, according to
REM Appveyor's documentation.
SET PATH=C:\Program Files (x86)\MSBuild\%TOOLCHAIN_VERSION%\Bin;%PATH%

set VCVARSALL="C:\Program Files (x86)\Microsoft Visual Studio %TOOLCHAIN_VERSION%\VC\vcvarsall.bat"

set TARGET_ARCH=x86_64
set TARGET_PROGRAM_FILES=%ProgramFiles%
call %VCVARSALL% amd64
if %ERRORLEVEL% NEQ 0 exit 1

REM vcvarsall turns echo off
echo on
set RUST_URL=https://static.rust-lang.org/dist/rust-%RUST%-%TARGET_ARCH%-pc-windows-msvc.msi
echo Downloading %RUST_URL%...
mkdir build
powershell -Command "(New-Object Net.WebClient).DownloadFile('%RUST_URL%', 'build\rust-%RUST%-%TARGET_ARCH%-pc-windows-msvc.msi')"
if %ERRORLEVEL% NEQ 0 (
  echo ...downloading failed.
  exit 1
)

start /wait msiexec /i build\rust-%RUST%-%TARGET_ARCH%-pc-windows-msvc.msi INSTALLDIR="%TARGET_PROGRAM_FILES%\Rust %RUST%" /quiet /qn /norestart
if %ERRORLEVEL% NEQ 0 exit 1

set PATH="%TARGET_PROGRAM_FILES%\Rust %RUST%\bin";%PATH%

if [%Configuration%] == [Release] (
    set CARGO_MODE=--release
    set TARGET=release
) else (
    set TARGET=debug
)

link /?
cl /?
rustc --version
cargo --version

cd rust-certitude

cargo build --verbose %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

cargo test --verbose %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

cargo doc --verbose
if %ERRORLEVEL% NEQ 0 exit 1

cargo clean --verbose
if %ERRORLEVEL% NEQ 0 exit 1

cd ..
cd c-certitude

cargo build --verbose %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

dir target\%TARGET%\

REM Move the .lib file to the name used in Rust nightly, if it exists.
if exist target\%TARGET%\c_certitude.lib (
    copy target\%TARGET%\c_certitude.lib target\%TARGET%\c_certitude.dll.lib
)
copy target\%TARGET%\c_certitude.dll .\c_certitude.dll
if %ERRORLEVEL% NEQ 0 exit 1

cl target\%TARGET%\c_certitude.dll.lib test/test.c
if %ERRORLEVEL% NEQ 0 exit 1

test.exe
if %ERRORLEVEL% NEQ 0 exit 1

