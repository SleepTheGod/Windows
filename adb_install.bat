@echo off

REM Download ADB platform tools
powershell -Command "& {Invoke-WebRequest -Uri 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip' -OutFile 'platform-tools.zip'}"

REM Extract the downloaded zip file
powershell -Command "& {Expand-Archive -Path 'platform-tools.zip' -DestinationPath 'E:\My USB\Installz\platform-tools'}"

REM Add ADB to the system's PATH environment variable
setx PATH "%PATH%;E:\My USB\Installz\platform-tools"

REM Clean up the downloaded zip file
del platform-tools.zip

echo ADB has been installed successfully!
