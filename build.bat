@echo off
:: build.bat -- Build VSM guest test tool and driver
::
:: Requires Visual Studio + WDK (same version).
:: Run from a WDK-enabled x64 command prompt (Developer Command Prompt
:: with the WDK environment, or use Visual Studio's x64 Native Tools
:: after setting WDK_DIR below).
::
:: Usage: build.bat [all | usermode | driver]

setlocal
set MODE=%~1
if "%MODE%"=="" set MODE=all

:: Paths -- adjust if needed
set WDK_INC=%WindowsSdkDir%Include\%WindowsSDKVersion%\km
set WDK_LIB=%WindowsSdkDir%Lib\%WindowsSDKVersion%\km\x64
set NTDDK_H=%WDK_INC%\ntddk.h

if not exist "%NTDDK_H%" (
    echo ERROR: WDK not found. Expected: %NTDDK_H%
    echo Set WindowsSdkDir and WindowsSDKVersion or run from a WDK command prompt.
    exit /b 1
)

:: -----------------------------------------------------------------------
:: User-mode test executable (vsm_test.exe)
:: -----------------------------------------------------------------------
if "%MODE%"=="all" goto :build_user
if "%MODE%"=="usermode" goto :build_user
goto :build_driver

:build_user
echo [1/2] Building vsm_test.exe (user-mode test suite)...
cl.exe /nologo /EHa /Zi /O2 /W3 ^
    vsm_test.cpp vsm_test_intel.cpp vsm_test_synth.cpp vsm_test_isolation.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
    ntdll.lib kernel32.lib advapi32.lib tbs.lib ^
    /OUT:vsm_test.exe
if errorlevel 1 (
    echo FAILED: vsm_test.exe
    exit /b 1
)
echo   -> vsm_test.exe OK

if "%MODE%"=="usermode" goto :done

:: -----------------------------------------------------------------------
:: Kernel driver (VsmTest.sys)
:: -----------------------------------------------------------------------
:build_driver
echo [2/2] Building VsmTest.sys (kernel driver)...

:: Assemble VMCALL stubs
ml64.exe /nologo /c /Cx vsm_vmcall.asm
if errorlevel 1 (
    echo FAILED: vsm_vmcall.asm
    exit /b 1
)
echo   -> vsm_vmcall.obj OK

:: Compile driver
cl.exe /nologo /kernel /O2 /GS- /W3 /Zi ^
    /I "%WDK_INC%" ^
    /D_AMD64_ /DAMD64 /D_WIN64 ^
    /D POOL_NX_OPTIN=1 ^
    /c vsm_ktest.c vsm_ktest_isolation.c
if errorlevel 1 (
    echo FAILED: vsm_ktest.c
    exit /b 1
)
echo   -> vsm_ktest.obj OK

:: Link driver
link.exe /nologo /DRIVER /NODEFAULTLIB ^
    /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /MACHINE:X64 ^
    /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
    /SECTION:INIT,d ^
    /LIBPATH:"%WDK_LIB%" ^
    ntoskrnl.lib ^
    vsm_ktest.obj vsm_ktest_isolation.obj vsm_vmcall.obj ^
    /OUT:VsmTest.sys ^
    /PDB:VsmTest.pdb
if errorlevel 1 (
    echo FAILED: link VsmTest.sys
    exit /b 1
)
echo   -> VsmTest.sys OK

:done
echo.
echo Build complete.
echo.
echo To run (requires test-signing or HVCI disabled for the driver):
echo   1. Enable test-signing:  bcdedit /set testsigning on  [reboot]
echo   2. Load driver:          sc create VsmTest type= kernel start= demand binPath= "%%CD%%\VsmTest.sys"
echo                            sc start  VsmTest
echo   3. Run tests:            vsm_test.exe
echo   4. Run single section:   vsm_test.exe 3     (section 3 = MBEC)
echo   5. Unload:               sc stop VsmTest ^& sc delete VsmTest
echo.
echo Note: If HVCI is active, the unsigned driver will be blocked.
echo Sign with a test cert or use a VM snapshot before HVCI is enabled.
endlocal
