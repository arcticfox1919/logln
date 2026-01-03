@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Logln Unit Test Build and Run Script
:: ============================================================================

:: Remove trailing backslash from %~dp0
set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "BUILD_DIR=%PROJECT_ROOT%\build"
set "BUILD_TYPE=Release"

:: Parse arguments
:parse_args
if "%~1"=="" goto :end_parse
if /i "%~1"=="--debug" set "BUILD_TYPE=Debug"
if /i "%~1"=="-d" set "BUILD_TYPE=Debug"
if /i "%~1"=="--clean" set "DO_CLEAN=1"
if /i "%~1"=="-c" set "DO_CLEAN=1"
if /i "%~1"=="--help" goto :show_help
if /i "%~1"=="-h" goto :show_help
shift
goto :parse_args
:end_parse

:: Show help
if defined SHOW_HELP goto :show_help

echo.
echo ============================================================
echo   Logln Unit Test Runner
echo ============================================================
echo   Build Type: %BUILD_TYPE%
echo   Build Dir:  %BUILD_DIR%
echo ============================================================
echo.

:: Clean build directory if requested
if defined DO_CLEAN (
    echo [1/4] Cleaning build directory...
    if exist "%BUILD_DIR%" (
        rmdir /s /q "%BUILD_DIR%"
        echo       Cleaned.
    ) else (
        echo       Nothing to clean.
    )
) else (
    echo [1/4] Skipping clean ^(use --clean to force^)
)

:: Create build directory
if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
)

:: Configure with CMake
echo.
echo [2/4] Configuring with CMake...
pushd "%BUILD_DIR%"
cmake "%PROJECT_ROOT%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DLOGLN_BUILD_TESTS=ON
set CMAKE_RESULT=%ERRORLEVEL%
popd
if %CMAKE_RESULT% neq 0 (
    echo.
    echo [ERROR] CMake configuration failed!
    exit /b 1
)

:: Build
echo.
echo [3/4] Building...
cmake --build "%BUILD_DIR%" --config %BUILD_TYPE% --parallel
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

:: Run tests
echo.
echo [4/4] Running tests...
echo.
ctest --test-dir "%BUILD_DIR%" --config %BUILD_TYPE% --output-on-failure --verbose
set TEST_RESULT=%ERRORLEVEL%

echo.
echo ============================================================
if %TEST_RESULT% equ 0 (
    echo   All tests PASSED!
) else (
    echo   Some tests FAILED!
)
echo ============================================================
echo.

exit /b %TEST_RESULT%

:show_help
echo.
echo Usage: run_tests.bat [options]
echo.
echo Options:
echo   -d, --debug    Build in Debug mode (default: Release)
echo   -c, --clean    Clean build directory before building
echo   -h, --help     Show this help message
echo.
echo Examples:
echo   run_tests.bat              Build and run tests in Release mode
echo   run_tests.bat --debug      Build and run tests in Debug mode
echo   run_tests.bat --clean      Clean build and run tests
echo   run_tests.bat -c -d        Clean build in Debug mode
echo.
exit /b 0
