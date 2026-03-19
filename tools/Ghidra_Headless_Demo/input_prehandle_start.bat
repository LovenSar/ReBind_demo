@echo off
setlocal enabledelayedexpansion

REM --- Configuration ---
REM Set Path to Ghidra's analyzeHeadless command
set "GHIDRA_CMD=E:\Program Files (x86)\ghidra_11.4.3_PUBLIC_20251203\ghidra_11.4.3_PUBLIC\support\analyzeHeadless.bat"

REM Set Ghidra Project Name (will be deleted and recreated for each file)
set "PROJECT_NAME=MyPEAnalysisTemp"
REM --- End Configuration ---

REM Get the directory where this batch script is located
set "SCRIPT_DIR=%~dp0"
REM Ensure SCRIPT_DIR has a trailing backslash for clean joins later if needed
if not "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR%\"

REM Check if a file or folder path was provided (e.g., via drag and drop)
if "%~1"=="" (
    echo Error: Please drag and drop a file onto this script.
    pause
    exit /b 1
)

REM Get the full path of the dropped item
set "INPUT_TARGET=%~f1" REM Use %~f1 to ensure full path

REM Check if the target exists
if not exist "%INPUT_TARGET%" (
    echo Error: Input file or folder does not exist: "%INPUT_TARGET%"
    pause
    exit /b 1
)

REM Determine if input is a file or directory
set "IS_DIR=0"
if exist "%INPUT_TARGET%\" set "IS_DIR=1"

REM --- MODIFICATION START: Reject folder input ---
if %IS_DIR% == 1 (
    echo Error: Input is a folder. This script only supports processing single files.
    echo Please drag and drop a file, not a folder.
    pause
    exit /b 1
)
REM --- MODIFICATION END ---

REM --- Since we exit above if it's a directory, we now know it's a file ---
REM Get the directory containing the input target and the target's name
set "INPUT_PARENT_DIR=%~dp1"
set "INPUT_NAME=%~n1"

REM Define the dedicated output and working directory relative to the input's location
set "WORK_OUTPUT_DIR=%INPUT_PARENT_DIR%\%INPUT_NAME%_ghidemo"

REM --- Preparation Steps ---

REM 1. Create the working/output directory
echo.
echo Preparing working directory: "%WORK_OUTPUT_DIR%"
if not exist "%WORK_OUTPUT_DIR%" (
    echo Creating directory...
    mkdir "%WORK_OUTPUT_DIR%"
    if errorlevel 1 (
        echo Error: Failed to create working/output directory. Check permissions.
        pause
        exit /b 1
    )
) else (
    echo Directory already exists. Files may be overwritten.
)

REM 2. Copy the input target (we know it's a file) to the working directory
echo Copying input file to working directory...
echo Copying file "%INPUT_TARGET%"...
copy /Y "%INPUT_TARGET%" "%WORK_OUTPUT_DIR%" > nul
if errorlevel 1 (
    echo Error: Failed to copy input file "%INPUT_TARGET%". Check permissions.
    pause
    exit /b 1
)
echo Preparation complete.
echo.

REM --- Filename Sanitization ---
REM (This part implicitly relies on %~1 being the file, which is true now)
set "ORIGINAL_NAME=%~nx1"
set "NEW_NAME="
set "ALLOWED_CHARS=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
set "TEMP_NAME=!ORIGINAL_NAME!"
:char_loop
if not defined TEMP_NAME goto :end_char_loop
set "char=!TEMP_NAME:~0,1!"
set "TEMP_NAME=!TEMP_NAME:~1!"
echo "!ALLOWED_CHARS!" | findstr /i /c:"!char!" > nul
if errorlevel 1 (
    set "NEW_NAME=!NEW_NAME!_"
) else (
    set "NEW_NAME=!NEW_NAME!!char!"
)
goto :char_loop
:end_char_loop
set "NAME_X=!NEW_NAME!"
echo Original Filename: %ORIGINAL_NAME%
echo Processed Filename: !NAME_X!


REM --- Processing Logic ---

REM Function to process a single file *within* the WORK_OUTPUT_DIR
:ProcessFileInWorkDir
    set "file_to_process_in_workdir=%~1"
    set "target_output_dir=%WORK_OUTPUT_DIR%"  REM Use second argument passed to function

    @REM REM ** Crucial Check **: Ensure arguments were received correctly (Optional Debug)
    @REM if not defined target_output_dir (
    @REM     echo ERROR in :ProcessFileInWorkDir - target_output_dir (Arg 2) is empty!
    @REM     echo Arg 1 was: "%file_to_process_in_workdir%"
    @REM     pause
    @REM     goto :eof
    @REM )
    @REM if not defined file_to_process_in_workdir (
    @REM     echo ERROR in :ProcessFileInWorkDir - file_to_process_in_workdir (Arg 1) is empty!
    @REM     pause
    @REM     goto :eof
    @REM )


    echo =====================================================================
    echo Processing File: "%file_to_process_in_workdir%"
    echo ExtractAll.py from: "%SCRIPT_DIR%"
    echo Output base: "%target_output_dir%"
    echo =====================================================================

    set "GHIDRA_PROJ=%TEMP%\rebind_g_%RANDOM%%RANDOM%"
    mkdir "%GHIDRA_PROJ%" 2>nul

    echo "%GHIDRA_CMD%" "%GHIDRA_PROJ%" proj -deleteProject -import "%file_to_process_in_workdir%" -scriptPath "%SCRIPT_DIR%" -postScript ExtractAll.py "%target_output_dir%" "!ORIGINAL_NAME!"
    call "%GHIDRA_CMD%" "%GHIDRA_PROJ%" proj -deleteProject -import "%file_to_process_in_workdir%" -scriptPath "%SCRIPT_DIR%" -postScript ExtractAll.py "%target_output_dir%" "!ORIGINAL_NAME!"

    rd /S /Q "%GHIDRA_PROJ%" 2>nul

    echo Cleaning up copied input and any stray .py in work dir...
    del /Q /F "%target_output_dir%\*.py" > nul 2>&1
    del /Q /F "%target_output_dir%\%ORIGINAL_NAME%" > nul 2>&1

    echo.
goto :eof


REM --- Main Execution ---

REM Since we exit early for directories, we only process the single file case now.
echo Processing the copied input file (now in "%WORK_OUTPUT_DIR%")...

REM Get the filename part of the original input target
for %%i in ("%INPUT_TARGET%") do set "INPUT_FILENAME=%%~nxi"

REM Prepare arguments for the function call
set "ARG1_PATH=%WORK_OUTPUT_DIR%\%INPUT_FILENAME%"
set "ARG2_PATH=%WORK_OUTPUT_DIR%"

REM Optional Debug: Check if variables are set correctly before the call
REM echo DEBUG: Arg1 = "%ARG1_PATH%"
REM echo DEBUG: Arg2 = "%ARG2_PATH%"

REM Call the processing function
call :ProcessFileInWorkDir "%ARG1_PATH%" "%ARG2_PATH%"


echo.
echo =====================================================================
echo All Processing completed!
echo Working directory and output location: "%WORK_OUTPUT_DIR%"
echo =====================================================================
pause
endlocal
exit /b 0