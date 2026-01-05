@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

REM Fail on first error
set CL_FLAGS=/nologo /W4 /WX /Z7 /std:c11

REM Get directory of this script
set THIS_DIR=%~dp0
pushd "%THIS_DIR%"

echo Building examples with cl.exe

cl %CL_FLAGS% /Fe01_basic.exe       01_basic.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe02_copy_tree.exe   02_copy_tree.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe03_file_info.exe   03_file_info.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe04_crc32.exe       04_crc32.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe05_walk_tree.exe   05_walk_tree.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe06_copy_move.exe   06_copy_move.c
if errorlevel 1 goto :fail

cl %CL_FLAGS% /Fe07_delete_tree.exe 07_delete_tree.c
if errorlevel 1 goto :fail

echo.
echo All examples built successfully.
goto :eof

:fail
echo.
echo Build failed.
exit /b 1
