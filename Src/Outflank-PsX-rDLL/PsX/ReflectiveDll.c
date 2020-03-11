#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Winver.h>
#include <shlwapi.h>
#include "ReflectiveLoader.h"
#include "psx.h"

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Shlwapi.lib")

PSECPROD pSecProducts[64] = { 0 };
DWORD dwMSProc = 0, dwNonMSProc = 0, dwSecProcCount = 0;

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

void EnumSecurityProc(LPWSTR lpCompany, LPWSTR lpDescription, DWORD dwPID) {
	pSecProducts[dwSecProcCount] = (PSECPROD)calloc(1, sizeof(SECPROD));

	LPCWSTR pwszCompany[26];
	pwszCompany[0] = L"ESET";
	pwszCompany[1] = L"McAfee";
	pwszCompany[2] = L"Symantec";
	pwszCompany[3] = L"Sophos";
	pwszCompany[4] = L"Panda";
	pwszCompany[5] = L"Bitdefender";
	pwszCompany[6] = L"Kaspersky";
	pwszCompany[7] = L"AVG";
	pwszCompany[8] = L"Avast";
	pwszCompany[9] = L"Trend Micro";
	pwszCompany[10] = L"F-Secure";
	pwszCompany[11] = L"Comodo";
	pwszCompany[12] = L"Cylance";
	pwszCompany[13] = L"CrowdStrike";
	pwszCompany[14] = L"Carbon Black";
	pwszCompany[15] = L"Palo Alto";
	pwszCompany[16] = L"SentinelOne";
	pwszCompany[17] = L"Endgame";
	pwszCompany[18] = L"Cisco";
	pwszCompany[19] = L"Splunk";
	pwszCompany[20] = L"LogRhythm";
	pwszCompany[21] = L"Rapid7";
	pwszCompany[22] = L"Sysinternals";
	pwszCompany[23] = L"FireEye";
	pwszCompany[24] = L"Cybereason";
	pwszCompany[25] = L"Ivanti";

	for (DWORD i = 0; i < 26; i++) {
		if (StrStrIW(lpCompany, pwszCompany[i])) {
			pSecProducts[dwSecProcCount]->dwPID = dwPID;
			pSecProducts[dwSecProcCount]->lpCompany = lpCompany;
			pSecProducts[dwSecProcCount]->lpDescription = lpDescription;
			dwSecProcCount++;
		}
	}

	//Windows Defender (ATP)
	if (StrStrIW(lpDescription, L"Antimalware Service Executable") || StrStrIW(lpDescription, L"Windows Defender")) {
		pSecProducts[dwSecProcCount]->dwPID = dwPID;
		pSecProducts[dwSecProcCount]->lpCompany = lpCompany;
		pSecProducts[dwSecProcCount]->lpDescription = lpDescription;
		dwSecProcCount++;
	}

	//Microsoft
	if (StrStrIW(lpCompany, L"Microsoft")) {
		dwMSProc++;
	}
	else {
		dwNonMSProc++;
	}

	return;
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

		EnumSecurityProc(lpCompany, lpDescription, (DWORD)ProcessId);
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


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	LPWSTR pwszParams = (LPWSTR)calloc(strlen((LPSTR)lpReserved) + 1, sizeof(WCHAR));
	size_t convertedChars = 0;
	size_t newsize = strlen((LPSTR)lpReserved) + 1;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		if (lpReserved != NULL) {

			// Handle the command line arguments.
			mbstowcs_s(&convertedChars, pwszParams, newsize, (LPSTR)lpReserved, _TRUNCATE);

			BOOL bIsElevated = FALSE;
			FILETIME ftCreate;
			SYSTEMTIME stUTC, stLocal;
			DWORD SessionID;
			DWORD dwTotalProc = 0, dwLowProc = 0, dwMediumProc = 0, dwHighProc = 0, dwSystemProc = 0;

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

			_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
			if (RtlInitUnicodeString == NULL) {
				return FALSE;
			}

			_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");
			if (RtlEqualUnicodeString == NULL) {
				return FALSE;
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

			UNICODE_STRING uLsass;
			UNICODE_STRING uWinlogon;
			RtlInitUnicodeString(&uLsass, L"lsass.exe");
			RtlInitUnicodeString(&uWinlogon, L"winlogon.exe");

			PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
		LOOP:do {
				pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

				wprintf(L"\n--------------------------------------------------------------------\n");
				wprintf(L"[+] ProcessName:\t %wZ\n", &pProcInfo->ProcessName);
				wprintf(L"    ProcessID:\t %d\n", (DWORD)pProcInfo->ProcessId);
				wprintf(L"    PPID:\t %d ", (DWORD)pProcInfo->InheritedFromProcessId);
				dwTotalProc++;

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

				// Exclude ProcessHandle on Lsass and WinLogon (Sysmon will log this). 
				if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
					goto LOOP;
				}
				if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uWinlogon, TRUE)) {
					goto LOOP;
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
						dwLowProc++;
					}
					else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
					{
						wprintf(L"    Integrity:\t Medium\n");
						dwMediumProc++;
					}
					else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
					{
						wprintf(L"    Integrity:\t High\n");
						dwHighProc++;
					}
					else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
					{
						wprintf(L"    Integrity:\t System\n");
						dwSystemProc++;
					}

					EnumPeb(hProcess);
					CloseHandle(hProcess);
				}

				if (pProcInfo->NextEntryDelta == 0) {
					break;
				}

			} while (pProcInfo);

			status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

			if (dwSecProcCount > 0) {
				wprintf(L"\n--------------------------------------------------------------------\n");
				wprintf(L"[!] Security products found (use psm <PID> or psh <PID> for detailed process info):\n");
				for (DWORD i = 0; i < dwSecProcCount; i++) {
					wprintf(L"    ProcessID:\t %d\n", pSecProducts[i]->dwPID);
					wprintf(L"    Vendor:\t %ls\n", pSecProducts[i]->lpCompany);
					wprintf(L"    Product:\t %ls\n\n", pSecProducts[i]->lpDescription);
				}
			}

			wprintf(L"--------------------------------------------------------------------\n");
			if (dwHighProc == 0 && dwSystemProc == 0) {
				wprintf(L"[+] Process summary (running in non-elevated security context):\n");
				wprintf(L"    Low integrity processes:    %d\n", dwLowProc);
				wprintf(L"    Medium integrity processes: %d\n", dwMediumProc);
			}
			else {
				wprintf(L"[I] Process summary (running in elevated security context):\n");
				wprintf(L"    Low integrity processes:    %d\n", dwLowProc);
				wprintf(L"    Medium integrity processes: %d\n", dwMediumProc);
				wprintf(L"    High integrity processes:   %d\n", dwHighProc);
				wprintf(L"    System integrity processes: %d\n", dwSystemProc);
			}

			wprintf(L"    Microsoft processes:        %d\n", dwMSProc);
			wprintf(L"    Non Microsoft processes:    %d\n\n", dwNonMSProc);

			wprintf(L"    Total active processes:     %d\n\n", dwTotalProc);
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
