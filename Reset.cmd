for /F "tokens=1,2,3 delims= " %%A in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RecoveryEnvironment" /v TargetOS') DO SET TARGETOS=%%C

for /F "tokens=1 delims=\" %%A in ('Echo %TARGETOS%') DO SET TARGETOSDRIVE=%%A

copy /y %TARGETOSDRIVE%\Recovery\OEM\Unattend.xml %TARGETOSDRIVE%\Windows\panther
copy /y %TARGETOSDRIVE%\Recovery\OEM\LayoutModification.xml %TARGETOSDRIVE%\Users\Default\AppData\Local\Microsoft\Windows\Shell\
copy /y %TARGETOSDRIVE%\Recovery\OEM\LayoutModification.json %TARGETOSDRIVE%\Users\Default\AppData\Local\Microsoft\Windows\Shell\
copy /y %TARGETOSDRIVE%\Recovery\OEM\TaskbarLayoutModification.xml %TARGETOSDRIVE%\Windows\OEM\
   
xcopy /cherky %TARGETOSDRIVE%\Recovery\OEM\Info %TARGETOSDRIVE%\Windows\System32\OOBE\info\

md %TARGETOSDRIVE%\Windows\ASUS\OOBEProc
echo if exist C:\Intel attrib +h C:\Intel >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\OOBEIns.cmd
echo if exist C:\PerfLogs attrib +h C:\PerfLogs >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\OOBEIns.cmd
echo attrib +h C:\*.* >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\OOBEIns.cmd
echo if exist C:\Intel attrib +h C:\Intel >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsLogonIns.cmd
echo if exist C:\PerfLogs attrib +h C:\PerfLogs >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsLogonIns.cmd
echo attrib +h C:\*.* >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsLogonIns.cmd
echo if exist C:\Intel attrib +h C:\Intel >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsusLogonIns.cmd
echo if exist C:\PerfLogs attrib +h C:\PerfLogs >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsusLogonIns.cmd
echo attrib +h C:\*.* >> %TARGETOSDRIVE%\Windows\ASUS\OOBEProc\AsusLogonIns.cmd


rem OEM setting
copy /y %TARGETOSDRIVE%\Windows\ASUS\Shortcuts\*.lnk %TARGETOSDRIVE%\Users\Public\Desktop\ 
del /s /q "%TARGETOSDRIVE%\Users\Public\Desktop\Media Player Center.lnk"
del /s /q "%TARGETOSDRIVE%\Users\Public\Desktop\Messenger Center.lnk"
del /s /q "%TARGETOSDRIVE%\ProgramData\Microsoft\Windows\Start Menu\Programs\Media Player Center.lnk"
del /s /q "%TARGETOSDRIVE%\ProgramData\Microsoft\Windows\Start Menu\Programs\Messenger Center.lnk"


rem Fix PC becomes sluggish
REG LOAD HKLM\TempReg "%TARGETOSDRIVE%\Windows\System32\config\SOFTWARE"
REG ADD "HKLM\TempReg\Microsoft\Windows Search" /v RebuildIndex /t REG_DWORD /d 7 /f
REG UNLOAD HKLM\TempReg   

   
rem Recovery Comman   
if exist %~dp0oemsetupRecovery.OEMTA.4287.cmd call %~dp0oemsetupRecovery.OEMTA.4287.cmd  
