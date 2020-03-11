#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wtsapi32.h>
#include <Winver.h>
#include "ReflectiveLoader.h"
#include "psc.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32")
#pragma comment(lib,"Version.lib") 

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

LPWSTR Utf8toUtf16(LPSTR lpAnsiString) {
	INT strLen = MultiByteToWideChar(CP_UTF8, 0, lpAnsiString, -1, NULL, 0);
	if (!strLen) {
		return NULL;
	}
	LPWSTR lpWideString = (LPWSTR)calloc(1, (strLen * sizeof(wchar_t)) + 1);
	if (!lpWideString) {
		return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, lpAnsiString, -1, lpWideString, strLen);

	return lpWideString;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	_NtQueryInformationToken NtQueryInformationToken = (_NtQueryInformationToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");
	if (NtQueryInformationToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		TOKEN_ELEVATION Elevation = { 0 };
		ULONG ReturnLength;

		status = NtQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &ReturnLength);
		if (status == STATUS_SUCCESS) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

DWORD IntegrityLevel(HANDLE hProcess) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	DWORD dwIntegrityLevel;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	_NtQueryInformationToken NtQueryInformationToken = (_NtQueryInformationToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");
	if (NtQueryInformationToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {

		status = NtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) {
			CloseHandle(hToken);
			return 0;
		}

		PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, ReturnLength);

		status = NtQueryInformationToken(hToken, TokenIntegrityLevel, pTIL, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			CloseHandle(hToken);
			return 0;
		}

		dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

		GlobalFree(pTIL);
		CloseHandle(hToken);

		return dwIntegrityLevel;
	}

	return 0;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	_NtQueryInformationToken NtQueryInformationToken = (_NtQueryInformationToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");
	if (NtQueryInformationToken == NULL) {
		return FALSE;
	}

	_NtAdjustPrivilegesToken NtAdjustPrivilegesToken = (_NtAdjustPrivilegesToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAdjustPrivilegesToken");
	if (NtAdjustPrivilegesToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

LPWSTR GetTokenUser(HANDLE hProcess) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	WCHAR lpName[MAX_NAME];
	WCHAR lpDomain[MAX_NAME];
	DWORD dwSize = MAX_NAME;
	SID_NAME_USE SidType;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return NULL;
	}

	_NtQueryInformationToken NtQueryInformationToken = (_NtQueryInformationToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");
	if (NtQueryInformationToken == NULL) {
		return NULL;
	}

	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		status = NtQueryInformationToken(hToken, TokenUser, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) {
			CloseHandle(hToken);
			return NULL;
		}

		PTOKEN_USER Ptoken_User = (PTOKEN_USER)GlobalAlloc(GPTR, ReturnLength);

		status = NtQueryInformationToken(hToken, TokenUser, Ptoken_User, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			CloseHandle(hToken);
			return NULL;
		}

		if (!LookupAccountSid(NULL, Ptoken_User->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
		{
			GlobalFree(Ptoken_User);
			CloseHandle(hToken);
			return NULL;
		}

		LPWSTR lpUser = (LPWSTR)calloc(MAX_NAME, 1);
		wcscat_s(lpUser, MAX_NAME, lpDomain);
		wcscat_s(lpUser, MAX_NAME, L"\\");
		wcscat_s(lpUser, MAX_NAME, lpName);

		GlobalFree(Ptoken_User);
		CloseHandle(hToken);

		return lpUser;
	}

	return NULL;
}

BOOL EnumPeb(HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	RTL_USER_PROCESS_PARAMETERS upp;
	WCHAR wcPathName[MAX_PATH] = { 0 };
	WCHAR wcCmdLine[8191] = { 0 };

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory");
	if (NtReadVirtualMemory == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	wprintf(L"    PEB Address:\t 0x%p\n", pbi.PebBaseAddress);

	status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, upp.ImagePathName.Buffer, &wcPathName, upp.ImagePathName.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, upp.CommandLine.Buffer, &wcCmdLine, upp.CommandLine.Length, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	wprintf(L"    ImagePath:\t %s\n", wcPathName);
	wprintf(L"    CommandLine:\t %s\n", wcCmdLine);

	return TRUE;
}

BOOL EnumFileProperties(HANDLE ProcessId) {
	SYSTEM_PROCESS_ID_INFORMATION pInfo;
	DWORD dwBinaryType = SCS_32BIT_BINARY;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return FALSE;
	}

	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		return FALSE;
	}

	_NtCreateFile NtCreateFile = (_NtCreateFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL) {
		return FALSE;
	}

	_NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
	if (NtFreeVirtualMemory == NULL) {
		return FALSE;
	}

	pInfo.ProcessId = ProcessId;
	pInfo.ImageName.Length = 0;
	pInfo.ImageName.MaximumLength = MAX_PATH;
	pInfo.ImageName.Buffer = NULL;

	SIZE_T uSize = pInfo.ImageName.MaximumLength;
	NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), &pInfo.ImageName.Buffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtQuerySystemInformation(SystemProcessIdInformation, &pInfo, sizeof(pInfo), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	HANDLE hFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &pInfo.ImageName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS Status = NtCreateFile(&hFile, (GENERIC_READ | SYNCHRONIZE), &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	WCHAR lpszFilePath[MAX_PATH + 1];
	DWORD dwResult = GetFinalPathNameByHandle(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
	if (dwResult == 0) {
		return FALSE;
	}
	else if (dwResult >= _countof(lpszFilePath)) {
		return FALSE;
	}

	LPWSTR pwszPath = NULL;
	wcstok_s(lpszFilePath, L"\\", &pwszPath);

	wprintf(L"    Path:\t %s\n", pwszPath);

	if (GetBinaryType(pwszPath, &dwBinaryType)) {
		if (dwBinaryType == SCS_64BIT_BINARY) {
			wprintf(L"    ImageType:\t 64-bit\n");
		}
		else {
			wprintf(L"    ImageType:\t 32-bit\n");
		}
	}

	DWORD dwHandle;
	DWORD dwLen = GetFileVersionInfoSize(pwszPath, &dwHandle);
	if (!dwLen) {
		return FALSE;
	}

	PBYTE lpVerInfo = (PBYTE)calloc(dwLen, sizeof(BYTE));
	if (!GetFileVersionInfo(pwszPath, dwHandle, dwLen, lpVerInfo)) {
		return FALSE;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	WCHAR wcCodePage[MAX_PATH] = { 0 };
	LPWSTR lpCompany = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
	LPWSTR lpDescription = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
	LPWSTR lpProductVersion = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
	UINT uLen;

	if (VerQueryValue(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
		swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

		lstrcat(lpCompany, L"\\StringFileInfo\\");
		lstrcat(lpCompany, wcCodePage);
		lstrcat(lpCompany, L"\\CompanyName");

		lstrcat(lpDescription, L"\\StringFileInfo\\");
		lstrcat(lpDescription, wcCodePage);
		lstrcat(lpDescription, L"\\FileDescription");

		lstrcat(lpProductVersion, L"\\StringFileInfo\\");
		lstrcat(lpProductVersion, wcCodePage);
		lstrcat(lpProductVersion, L"\\ProductVersion");

		if (VerQueryValue(lpVerInfo, lpCompany, (void **)&lpCompany, &uLen)) {
			wprintf(L"    CompanyName:\t %s\n", lpCompany);
		}
		if (VerQueryValue(lpVerInfo, lpDescription, (void **)&lpDescription, &uLen)) {
			wprintf(L"    Description:\t %s\n", lpDescription);
		}
		if (VerQueryValue(lpVerInfo, lpProductVersion, (void **)&lpProductVersion, &uLen)) {
			wprintf(L"    Version:\t %s\n", lpProductVersion);
		}
	}

	status = NtFreeVirtualMemory(NtCurrentProcess(), &pInfo.ImageName.Buffer, &uSize, MEM_RELEASE);

	CloseHandle(hFile);
	return TRUE;
}

BOOL EnumKernel() {
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	LPWSTR lpwKernelPath = NULL;
	DWORD dwBinaryType = SCS_32BIT_BINARY;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return FALSE;
	}

	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_NtCreateFile NtCreateFile = (_NtCreateFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL) {
		return FALSE;
	}

	_NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
	if (NtFreeVirtualMemory == NULL) {
		return FALSE;
	}

	ULONG uReturnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, 0, 0, &uReturnLength);
	if (!status == 0xc0000004) {
		return FALSE;
	}

	LPVOID pBuffer = NULL;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtQuerySystemInformation(SystemModuleInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	kernelBase = pModuleInfo->Module[0].ImageBase;
	kernelImage = pModuleInfo->Module[0].FullPathName;

	lpwKernelPath = Utf8toUtf16(pModuleInfo->Module[0].FullPathName);
	if (lpwKernelPath != NULL) {
		UNICODE_STRING uKernel;
		RtlInitUnicodeString(&uKernel, lpwKernelPath);

		HANDLE hFile = NULL;
		IO_STATUS_BLOCK IoStatusBlock;
		ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
		OBJECT_ATTRIBUTES FileObjectAttributes;
		InitializeObjectAttributes(&FileObjectAttributes, &uKernel, OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS Status = NtCreateFile(&hFile, (GENERIC_READ | SYNCHRONIZE), &FileObjectAttributes, &IoStatusBlock, 0,
			0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (hFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		WCHAR lpszFilePath[MAX_PATH + 1];
		DWORD dwResult = GetFinalPathNameByHandle(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
		if (dwResult == 0) {
			CloseHandle(hFile);
			return FALSE;
		}
		else if (dwResult >= _countof(lpszFilePath)) {
			CloseHandle(hFile);
			return FALSE;
		}

		LPWSTR pwszPath = NULL;
		wcstok_s(lpszFilePath, L"\\", &pwszPath);

		wprintf(L"    Path:\t %s\n", pwszPath);
		wprintf(L"    BaseAddress:\t 0x%p \n", kernelBase);

		if (GetBinaryType(pwszPath, &dwBinaryType)) {
			if (dwBinaryType == SCS_64BIT_BINARY) {
				wprintf(L"    ImageType:\t 64-bit\n");
			}
			else {
				wprintf(L"    ImageType:\t 32-bit\n");
			}
		}

		DWORD dwHandle;
		DWORD dwLen = GetFileVersionInfoSize(pwszPath, &dwHandle);
		if (!dwLen) {
			CloseHandle(hFile);
			return FALSE;
		}

		PBYTE lpVerInfo = (PBYTE)calloc(dwLen, sizeof(BYTE));
		if (!GetFileVersionInfo(pwszPath, dwHandle, dwLen, lpVerInfo)) {
			CloseHandle(hFile);
			return FALSE;
		}

		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		WCHAR wcCodePage[MAX_PATH] = { 0 };
		LPWSTR lpCompany = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
		LPWSTR lpDescription = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
		LPWSTR lpProductVersion = (LPWSTR)calloc(MAX_PATH, sizeof(WCHAR));
		UINT uLen;

		if (VerQueryValue(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
			swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

			lstrcat(lpCompany, L"\\StringFileInfo\\");
			lstrcat(lpCompany, wcCodePage);
			lstrcat(lpCompany, L"\\CompanyName");

			lstrcat(lpDescription, L"\\StringFileInfo\\");
			lstrcat(lpDescription, wcCodePage);
			lstrcat(lpDescription, L"\\FileDescription");

			lstrcat(lpProductVersion, L"\\StringFileInfo\\");
			lstrcat(lpProductVersion, wcCodePage);
			lstrcat(lpProductVersion, L"\\ProductVersion");

			if (VerQueryValue(lpVerInfo, lpCompany, (void **)&lpCompany, &uLen)) {
				wprintf(L"    CompanyName:\t %s\n", lpCompany);
			}
			if (VerQueryValue(lpVerInfo, lpDescription, (void **)&lpDescription, &uLen)) {
				wprintf(L"    Description:\t %s\n", lpDescription);
			}
			if (VerQueryValue(lpVerInfo, lpProductVersion, (void **)&lpProductVersion, &uLen)) {
				wprintf(L"    Version:\t %s\n", lpProductVersion);
			}
		}

		CloseHandle(hFile);
	}
	else {
		wprintf(L"    KernelImage:\t %hs \n", kernelImage);
		wprintf(L"    BaseAddress:\t 0x%p \n", kernelBase);
	}

	status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

	return TRUE;
}

BOOL EnumRDPSessions() {
	WTS_SESSION_INFOW *pSessions;
	DWORD pCount;

	if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &pCount)) {
		WTSFreeMemory(pSessions);
		return FALSE;
	}

	for (DWORD i = 0; i < pCount; i++)
	{
		LPWSTR lpUserName = NULL;
		LPWSTR lpDomainName = NULL;
		LPWSTR lpClientAddress = NULL;
		DWORD pBytesReturned;

		if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSUserName, &lpUserName, &pBytesReturned)) {
			WTSFreeMemory(pSessions);
			return FALSE;
		}

		if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSDomainName, &lpDomainName, &pBytesReturned)) {
			WTSFreeMemory(pSessions);
			return FALSE;
		}

		if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessions[i].SessionId, WTSClientAddress, &lpClientAddress, &pBytesReturned)) {
			WTSFreeMemory(pSessions);
			return FALSE;
		}

		PWTS_CLIENT_ADDRESS pAddress = (PWTS_CLIENT_ADDRESS)lpClientAddress;

		if (_wcsicmp(lpUserName, L"") != 0) {
			wprintf(L"\n<R> RDP Session:\t %d\n", pSessions[i].SessionId);
			wprintf(L"    UserName:\t %s\\%s\n", lpDomainName, lpUserName);
			switch (pSessions[i].State) {
			case WTSActive:
				wprintf(L"    State:\t Active\n");
				break;
			case WTSConnected:
				wprintf(L"    State:\t Connected\n");
				break;
			case WTSConnectQuery:
				wprintf(L"    State:\t Connecting\n");
				break;
			case WTSShadow:
				wprintf(L"    State:\t Shadowing\n");
				break;
			case WTSDisconnected:
				wprintf(L"    State:\t Disconnected\n");
				break;
			case WTSIdle:
				wprintf(L"    State:\t Idle\n");
				break;
			case WTSListen:
				wprintf(L"    State:\t Listening\n");
				break;
			case WTSReset:
				wprintf(L"    State:\t Reset\n");
				break;
			case WTSDown:
				wprintf(L"    State:\t Down\n");
				break;
			case WTSInit:
				wprintf(L"    State:\t Initialization\n");
				break;
			default:
				wprintf(L"    State:\t %d\n", pSessions[i].State);
			}

			if (_wcsicmp(pSessions[i].pWinStationName, L"") != 0) {
				wprintf(L"    Name:\t %s\n", pSessions[i].pWinStationName);
			}

			if (AF_INET == pAddress->AddressFamily)
			{
				wprintf(L"    ClientAddr:\t %d.%d.%d.%d\n", pAddress->Address[2], pAddress->Address[3], pAddress->Address[4], pAddress->Address[5]);
			}
			else if (AF_INET6 == pAddress->AddressFamily)
			{
				wprintf(L"    ClientAddr:\t %x:%x:%x:%x:%x:%x:%x:%x\n",
					pAddress->Address[2] << 8 | pAddress->Address[3],
					pAddress->Address[4] << 8 | pAddress->Address[5],
					pAddress->Address[6] << 8 | pAddress->Address[7],
					pAddress->Address[8] << 8 | pAddress->Address[9],
					pAddress->Address[10] << 8 | pAddress->Address[11],
					pAddress->Address[12] << 8 | pAddress->Address[13],
					pAddress->Address[14] << 8 | pAddress->Address[15],
					pAddress->Address[16] << 8 | pAddress->Address[17]);
			}
		}
	}

	WTSFreeMemory(pSessions);

	return TRUE;
}

BOOL CheckConnectedProc(DWORD ProcessId) {
	PMIB_TCPTABLE2 pTcpTable;
	PMIB_TCP6TABLE2 pTcp6Table;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	int i;

	pTcpTable = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, (sizeof(MIB_TCPTABLE2)));
	if (pTcpTable == NULL) {
		return FALSE;
	}

	ulSize = sizeof(MIB_TCPTABLE);

	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		pTcpTable = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, (ulSize));
		if (pTcpTable == NULL) {
			return FALSE;
		}
	}

	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					HeapFree(GetProcessHeap(), 0, (pTcpTable));
					return TRUE;
				}
			}
		}
	}

	pTcp6Table = (MIB_TCP6TABLE2 *)HeapAlloc(GetProcessHeap(), 0, (sizeof(MIB_TCPTABLE2)));
	if (pTcp6Table == NULL) {
		return FALSE;
	}

	ulSize = sizeof(MIB_TCP6TABLE);

	if ((dwRetVal = GetTcp6Table2(pTcp6Table, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		HeapFree(GetProcessHeap(), 0, (pTcp6Table));
		pTcp6Table = (MIB_TCP6TABLE2 *)HeapAlloc(GetProcessHeap(), 0, (ulSize));
		if (pTcp6Table == NULL) {
			return FALSE;
		}
	}

	if ((dwRetVal = GetTcp6Table2(pTcp6Table, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcp6Table->dwNumEntries; i++) {
			if (pTcp6Table->table[i].dwOwningPid == ProcessId) {
				if (pTcp6Table->table[i].State == MIB_TCP_STATE_ESTAB) {
					HeapFree(GetProcessHeap(), 0, (pTcp6Table));
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL GetTcpSessions(DWORD ProcessId) {
	PMIB_TCPTABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	WCHAR szLocalAddr[128];
	WCHAR szRemoteAddr[128];
	BOOL bRDPConnected = FALSE;
	struct in_addr IpAddr;
	int i;

	pTcpTable = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, (sizeof(MIB_TCPTABLE2)));
	if (pTcpTable == NULL) {
		return FALSE;
	}

	ulSize = sizeof(MIB_TCPTABLE);

	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		pTcpTable = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, (ulSize));
		if (pTcpTable == NULL) {
			return FALSE;
		}
	}

	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					wprintf(L"\n<-> Session:\t TCP\n");
					wprintf(L"    State:\t ESTABLISHED\n");

					_RtlIpv4AddressToStringW RtlIpv4AddressToStringW = (_RtlIpv4AddressToStringW)
						GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlIpv4AddressToStringW");
					if (RtlIpv4AddressToStringW == NULL) {
						return FALSE;
					}

					IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
					RtlIpv4AddressToStringW(&IpAddr, szLocalAddr);
					wprintf(L"    Local Addr:\t %s:%d\n", szLocalAddr, ntohs((u_short)pTcpTable->table[i].dwLocalPort));

					IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
					RtlIpv4AddressToStringW(&IpAddr, szRemoteAddr);
					wprintf(L"    Remote Addr:\t %s:%d\n", szRemoteAddr, ntohs((u_short)pTcpTable->table[i].dwRemotePort));
				}

				if (ntohs((u_short)pTcpTable->table[i].dwLocalPort) == 3389) {
					bRDPConnected = TRUE;
				}
			}
		}
	}
	else {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		return FALSE;
	}

	if (pTcpTable != NULL) {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		pTcpTable = NULL;
	}

	if (bRDPConnected) {
		EnumRDPSessions();
	}

	return FALSE;
}

BOOL GetTcp6Sessions(DWORD ProcessId) {
	PMIB_TCP6TABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;
	WCHAR szLocalAddr[128];
	WCHAR szRemoteAddr[128];
	BOOL bRDPConnected = FALSE;
	int i;

	pTcpTable = (MIB_TCP6TABLE2 *)HeapAlloc(GetProcessHeap(), 0, (sizeof(MIB_TCPTABLE2)));
	if (pTcpTable == NULL) {
		return FALSE;
	}

	ulSize = sizeof(MIB_TCP6TABLE);

	if ((dwRetVal = GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		pTcpTable = (MIB_TCP6TABLE2 *)HeapAlloc(GetProcessHeap(), 0, (ulSize));
		if (pTcpTable == NULL) {
			return FALSE;
		}
	}

	if ((dwRetVal = GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			if (pTcpTable->table[i].dwOwningPid == ProcessId) {
				if (pTcpTable->table[i].State == MIB_TCP_STATE_ESTAB) {
					wprintf(L"\n<-> Session:\t TCP6\n");
					wprintf(L"    State:\t ESTABLISHED\n");

					_RtlIpv6AddressToStringW RtlIpv6AddressToStringW = (_RtlIpv6AddressToStringW)
						GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlIpv6AddressToStringW");
					if (RtlIpv6AddressToStringW == NULL) {
						return FALSE;
					}

					RtlIpv6AddressToStringW(&pTcpTable->table[i].LocalAddr, szLocalAddr);
					if (_wcsicmp(szLocalAddr, L"::") == 0) {
						wprintf(L"    Local Addr:\t [0:0:0:0:0:0:0:0]:%d\n", ntohs((u_short)pTcpTable->table[i].dwLocalPort));
					}
					else {
						wprintf(L"    Local Addr:\t [%s]:%d\n", szLocalAddr, ntohs((u_short)pTcpTable->table[i].dwLocalPort));
					}

					RtlIpv6AddressToStringW(&pTcpTable->table[i].RemoteAddr, szRemoteAddr);
					if (_wcsicmp(szRemoteAddr, L"::") == 0) {
						wprintf(L"    Remote Addr:\t [0:0:0:0:0:0:0:0]:%d\n", ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					}
					else {
						wprintf(L"    Remote Addr:\t [%s]:%d\n", szRemoteAddr, ntohs((u_short)pTcpTable->table[i].dwRemotePort));
					}

					if (ntohs((u_short)pTcpTable->table[i].dwLocalPort) == 3389) {
						bRDPConnected = TRUE;
					}
				}
			}
		}
	}
	else {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		return FALSE;
	}

	if (pTcpTable != NULL) {
		HeapFree(GetProcessHeap(), 0, (pTcpTable));
		pTcpTable = NULL;
	}

	if (bRDPConnected) {
		EnumRDPSessions();
	}

	return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		if (lpReserved != NULL) {
			BOOL bIsElevated = FALSE;
			FILETIME ftCreate;
			SYSTEMTIME stUTC, stLocal;
			DWORD SessionID;

			_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
			if (NtQuerySystemInformation == NULL) {
				exit(1);
			}

			_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
			if (NtAllocateVirtualMemory == NULL) {
				exit(1);
			}

			_NtOpenProcess NtOpenProcess = (_NtOpenProcess)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcess");
			if (NtOpenProcess == NULL) {
				exit(1);
			}

			_NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
			if (NtFreeVirtualMemory == NULL) {
				exit(1);
			}

			ULONG uReturnLength = 0;
			NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
			if (!status == 0xc0000004) {
				exit(1);
			}

			LPVOID pBuffer = NULL;
			SIZE_T uSize = uReturnLength;
			status = NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
			if (status != STATUS_SUCCESS) {
				exit(1);
			}

			status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
			if (status != STATUS_SUCCESS) {
				exit(1);
			}

			if (IsElevated()) {
				SetDebugPrivilege();
			}

			PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
		LOOP:do {
			pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

			if (!CheckConnectedProc((DWORD)pProcInfo->ProcessId)) {
				if (pProcInfo->NextEntryDelta == 0) {
					break;
				}

				goto LOOP;
			}

			wprintf(L"\n--------------------------------------------------------------------\n");
			wprintf(L"[+] ProcessName:\t %wZ\n", &pProcInfo->ProcessName);
			wprintf(L"    ProcessID:\t %d\n", (DWORD)pProcInfo->ProcessId);
			wprintf(L"    PPID:\t %d ", (DWORD)pProcInfo->InheritedFromProcessId);

			PSYSTEM_PROCESSES pParentInfo = (PSYSTEM_PROCESSES)pBuffer;
			do {
				pParentInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pParentInfo) + pParentInfo->NextEntryDelta);

				if ((DWORD)pParentInfo->ProcessId == (DWORD)pProcInfo->InheritedFromProcessId) {
					wprintf(L"(%wZ)\n", &pParentInfo->ProcessName);
					break;
				}
				else if (pParentInfo->NextEntryDelta == 0) {
					wprintf(L"(Non-existent process)\n");
					break;
				}

			} while (pParentInfo);

			ftCreate.dwLowDateTime = pProcInfo->CreateTime.LowPart;
			ftCreate.dwHighDateTime = pProcInfo->CreateTime.HighPart;

			// Convert the Createtime to local time.
			FileTimeToSystemTime(&ftCreate, &stUTC);
			if (SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
				wprintf(L"    CreateTime:\t %02d/%02d/%d %02d:%02d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute);
			}

			if (ProcessIdToSessionId((DWORD)pProcInfo->ProcessId, &SessionID)) {
				wprintf(L"    SessionID:\t %d\n", SessionID);
			}

			if ((DWORD)pProcInfo->ProcessId == 4) {
				EnumKernel();
			}
			else {
				EnumFileProperties(pProcInfo->ProcessId);
			}

			HANDLE hProcess = NULL;
			OBJECT_ATTRIBUTES ObjectAttributes;
			InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
			CLIENT_ID uPid = { 0 };

			uPid.UniqueProcess = pProcInfo->ProcessId;
			uPid.UniqueThread = (HANDLE)0;

			NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
			if (hProcess != NULL) {
				LPWSTR chUserName = GetTokenUser(hProcess);
				if (chUserName != NULL) {
					wprintf(L"    UserName:\t %s\n", chUserName);
					chUserName = NULL;
				}

				DWORD dwIntegrityLevel = IntegrityLevel(hProcess);
				if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
				{
					wprintf(L"    Integrity:\t Low\n");
				}
				else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
				{
					wprintf(L"    Integrity:\t Medium\n");
				}
				else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
				{
					wprintf(L"    Integrity:\t High\n");
				}
				else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
				{
					wprintf(L"    Integrity:\t System\n");
				}

				EnumPeb(hProcess);
				CloseHandle(hProcess);
			}

			GetTcpSessions((DWORD)pProcInfo->ProcessId);
			GetTcp6Sessions((DWORD)pProcInfo->ProcessId);

			if (pProcInfo->NextEntryDelta == 0) {
				break;
			}

		} while (pProcInfo);

		status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
		}

		// Flush STDOUT
		fflush(stdout);

		// We're done, so let's exit
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
