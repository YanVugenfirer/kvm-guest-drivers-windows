@echo off
call ..\tools\build.bat viostor.sln "Wxp Wnet Wlh Win7 Win8 Win10" %*
if errorlevel 1 goto :eof
call ..\tools\build.bat viostor.vcxproj "Win8_SDV Win10_SDV" %*
