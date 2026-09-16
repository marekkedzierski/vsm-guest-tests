@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d "C:\Users\ALIENWARE\Desktop\vsm_guest_tests"
call "C:\Users\ALIENWARE\Desktop\vsm_guest_tests\build.bat" usermode
