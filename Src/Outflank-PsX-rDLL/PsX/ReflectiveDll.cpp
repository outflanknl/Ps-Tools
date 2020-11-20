#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include <Winver.h>
#include <shlwapi.h>

#include "ReflectiveLoader.h"
#include "psx.h"

#define MAX_BUF 8192
#define MAX_SEC_PRD 20

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Shlwapi.lib")

LPCWSTR lpwPsXVersion = L"2.0_RedELK)";
PSECPROD pSecProducts[MAX_SEC_PRD] = { 0 };
DWORD dwMSProc = 0, dwNonMSProc = 0, dwSecProcCount = 0;

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

LPWSTR Utf8ToUtf16(_In_ LPSTR lpAnsiString) {
	INT strLen = MultiByteToWideChar(CP_UTF8, 0, lpAnsiString, -1, NULL, 0);
	if (!strLen) {
		return NULL;
	}

	LPWSTR lpWideString = (LPWSTR)calloc(strLen + 1, sizeof(WCHAR));
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

	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	return fRet;
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

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
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

LPWSTR GetProcessUser(IN HANDLE hProcess, BOOL bCloseHandle, BOOL bReturnDomainname, BOOL bReturnUsername) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	PTOKEN_USER Ptoken_User = NULL;
	WCHAR lpName[MAX_NAME];
	WCHAR lpDomain[MAX_NAME];
	DWORD dwSize = MAX_NAME;
	LPWSTR lpwUser = NULL;
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
			goto CleanUp;
		}

		Ptoken_User = (PTOKEN_USER)GlobalAlloc(GPTR, ReturnLength);

		status = NtQueryInformationToken(hToken, TokenUser, Ptoken_User, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		if (!LookupAccountSid(NULL, Ptoken_User->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType)) {
			goto CleanUp;
		}

		lpwUser = (LPWSTR)calloc(MAX_NAME, sizeof(WCHAR));
		if (bReturnDomainname) {
			wcscat_s(lpwUser, MAX_NAME, lpDomain);
			if (bReturnUsername) {
				wcscat_s(lpwUser, MAX_NAME, L"\\");
			}
		}
		if (bReturnUsername) {
			wcscat_s(lpwUser, MAX_NAME, lpName);
		}
	}

CleanUp:

	RtlSecureZeroMemory(lpName, MAX_NAME * sizeof(WCHAR));
	RtlSecureZeroMemory(lpDomain, MAX_NAME * sizeof(WCHAR));

	if (hProcess != NULL && bCloseHandle) {
		CloseHandle(hProcess);
	}

	if (hToken != NULL) {
		GlobalFree(Ptoken_User);
		CloseHandle(hToken);
	}
	else {
		return NULL;
	}

	return lpwUser;
}

DWORD IntegrityLevel(IN HANDLE hProcess) {
	HANDLE hToken = NULL;
	ULONG ReturnLength;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;
	DWORD dwRet = 0;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return 0;
	}

	_NtQueryInformationToken NtQueryInformationToken = (_NtQueryInformationToken)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");
	if (NtQueryInformationToken == NULL) {
		return 0;
	}

	_RtlSubAuthoritySid RtlSubAuthoritySid = (_RtlSubAuthoritySid)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlSubAuthoritySid");
	if (RtlSubAuthoritySid == NULL) {
		return 0;
	}

	_RtlSubAuthorityCountSid RtlSubAuthorityCountSid = (_RtlSubAuthorityCountSid)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlSubAuthorityCountSid");
	if (RtlSubAuthorityCountSid == NULL) {
		return 0;
	}

	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {

		status = NtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) {
			goto CleanUp;
		}

		pTIL = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, ReturnLength);

		status = NtQueryInformationToken(hToken, TokenIntegrityLevel, pTIL, ReturnLength, &ReturnLength);
		if (status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		dwIntegrityLevel = *RtlSubAuthoritySid(pTIL->Label.Sid, (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));

		if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
			dwRet = LowIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
			dwRet = MediumIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
			dwRet = HighIntegrity;
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
			dwRet = SystemIntegrity;
		}
		else {
			goto CleanUp;
		}
	}

CleanUp:

	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	if (pTIL != NULL) {
		GlobalFree(pTIL);
	}

	return dwRet;
}

BOOL EnumSecurityProc(IN LPWSTR lpCompany, IN LPWSTR lpDescription, IN DWORD dwPID) {
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

	const DWORD dwSize = _countof(pwszCompany);
	for (DWORD i = 0; i < dwSize && dwSecProcCount < MAX_SEC_PRD; i++) {
		if (StrStrIW(lpCompany, pwszCompany[i])) {
			pSecProducts[dwSecProcCount]->dwPID = dwPID;
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcCompany, lpCompany, MAX_PATH);
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcDescription, lpDescription, MAX_PATH);
			dwSecProcCount++;
		}
	}

	if (dwSecProcCount < MAX_SEC_PRD) {
		//Windows Defender (ATP)
		if (StrStrIW(lpDescription, L"Antimalware Service Executable") || StrStrIW(lpDescription, L"Windows Defender")) {
			pSecProducts[dwSecProcCount]->dwPID = dwPID;
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcCompany, lpCompany, MAX_PATH);
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcDescription, lpDescription, MAX_PATH);
			dwSecProcCount++;
		}
	}

	if (dwSecProcCount < MAX_SEC_PRD) {
		//Carbon Black
		if (StrStrIW(lpDescription, L"Carbon Black")) {
			pSecProducts[dwSecProcCount]->dwPID = dwPID;
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcCompany, lpCompany, MAX_PATH);
			RtlCopyMemory(pSecProducts[dwSecProcCount]->wcDescription, lpDescription, MAX_PATH);
			dwSecProcCount++;
		}
	}

	//MS
	if (StrStrIW(lpCompany, L"Microsoft")) {
		dwMSProc++;
	}
	else {
		dwNonMSProc++;
	}

	RtlZeroMemory(pwszCompany, sizeof(pwszCompany));

	return TRUE;
}

BOOL PrintSummary(IN LPSTREAM lpStream, DWORD dwTotalProc, DWORD dwLowProc, DWORD dwMediumProc, DWORD dwHighProc, DWORD dwSystemProc) {
	HRESULT hr = S_OK;
	WCHAR chBuffer[MAX_BUF] = { 0 };
	DWORD dwWritten = 0;

	if (dwSecProcCount > 0) {
		swprintf_s(chBuffer, _countof(chBuffer), L"\n--------------------------------------------------------------------\n");
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"[!] Security products found: %d\n", dwSecProcCount);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		for (DWORD i = 0; i < dwSecProcCount; i++) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    ProcessID:\t %d\n", pSecProducts[i]->dwPID);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				return FALSE;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));

			swprintf_s(chBuffer, _countof(chBuffer), L"    Vendor:\t %ls\n", pSecProducts[i]->wcCompany);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				return FALSE;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));

			swprintf_s(chBuffer, _countof(chBuffer), L"    Product:\t %ls\n\n", pSecProducts[i]->wcDescription);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				return FALSE;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
	}
	swprintf_s(chBuffer, _countof(chBuffer), L"--------------------------------------------------------------------\n");
	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	if (dwHighProc == 0 && dwSystemProc == 0) {
		swprintf_s(chBuffer, _countof(chBuffer), L"[S] Process summary (running in non-elevated security context):\n");
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		if (dwMediumProc > 0) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    Low integrity processes:    %d\n", dwLowProc);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				return FALSE;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));

			swprintf_s(chBuffer, _countof(chBuffer), L"    Medium integrity processes: %d\n", dwMediumProc);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				return FALSE;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
	}
	else {
		swprintf_s(chBuffer, _countof(chBuffer), L"[I] Process summary (running in elevated security context):\n");
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"    Low integrity processes:    %d\n", dwLowProc);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"    Medium integrity processes: %d\n", dwMediumProc);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"    High integrity processes:   %d\n", dwHighProc);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"    System integrity processes: %d\n", dwSystemProc);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			return FALSE;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));
	}

	swprintf_s(chBuffer, _countof(chBuffer), L"    Microsoft processes:        %d\n", dwMSProc);
	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	RtlZeroMemory(chBuffer, _countof(chBuffer));

	swprintf_s(chBuffer, _countof(chBuffer), L"    Non Microsoft processes:    %d\n\n", dwNonMSProc);
	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	RtlZeroMemory(chBuffer, _countof(chBuffer));

	swprintf_s(chBuffer, _countof(chBuffer), L"    Total active processes:     %d\n\n", dwTotalProc);
	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	RtlZeroMemory(chBuffer, _countof(chBuffer));

	return TRUE;
}

BOOL EnumPeb(HANDLE hProcess, IN LPSTREAM lpStream) {
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	RTL_USER_PROCESS_PARAMETERS upp;
	HRESULT hr = S_OK;
	WCHAR chReadBuf[MAX_BUF] = { 0 };
	WCHAR chWriteBuf[MAX_BUF] = { 0 };
	DWORD dwWritten = 0;

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

	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = NtReadVirtualMemory(hProcess, upp.ImagePathName.Buffer, &chReadBuf, upp.ImagePathName.MaximumLength, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	swprintf_s(chWriteBuf, _countof(chWriteBuf), L"    ImagePath:   %ls\n", chReadBuf);
	if (FAILED(hr = lpStream->Write(chWriteBuf, (ULONG)wcslen(chWriteBuf) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	RtlZeroMemory(chReadBuf, _countof(chReadBuf));
	RtlZeroMemory(chWriteBuf, _countof(chWriteBuf));

	status = NtReadVirtualMemory(hProcess, upp.CommandLine.Buffer, &chReadBuf, upp.CommandLine.MaximumLength, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	swprintf_s(chWriteBuf, _countof(chWriteBuf), L"    CommandLine: %ls\n", chReadBuf);
	if (FAILED(hr = lpStream->Write(chWriteBuf, (ULONG)wcslen(chWriteBuf) * sizeof(WCHAR), &dwWritten))) {
		return FALSE;
	}

	RtlZeroMemory(chReadBuf, _countof(chReadBuf));
	RtlZeroMemory(chWriteBuf, _countof(chWriteBuf));

	return TRUE;
}

BOOL EnumFileProperties(IN HANDLE ProcessId, IN LPSTREAM lpStream) {
	NTSTATUS status;
	DWORD dwResult;
	WCHAR lpszFilePath[MAX_PATH] = { 0 };
	LPWSTR pwszPath = NULL;
	DWORD dwLen = 0;
	SYSTEM_PROCESS_ID_INFORMATION pInfo;
	HANDLE hFile = NULL;
	HRESULT hr = S_OK;
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	WCHAR chBuffer[MAX_BUF] = { 0 };
	WCHAR wcCodePage[MAX_PATH] = { 0 };
	WCHAR wcCompanyName[MAX_PATH] = { 0 };
	WCHAR wcDescription[MAX_PATH] = { 0 };
	WCHAR wcProductVersion[MAX_PATH] = { 0 };
	PBYTE lpVerInfo = NULL;
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;
	DWORD dwWritten = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return FALSE;
	}

	_NtCreateFile NtCreateFile = (_NtCreateFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL) {
		return FALSE;
	}

	pInfo.ProcessId = ProcessId;
	pInfo.ImageName.Length = 0;
	pInfo.ImageName.MaximumLength = MAX_PATH;
	pInfo.ImageName.Buffer = NULL;

	pInfo.ImageName.Buffer = (PWSTR)calloc(pInfo.ImageName.MaximumLength, sizeof(WCHAR));

	status = NtQuerySystemInformation(SystemProcessIdInformation, &pInfo, sizeof(pInfo), NULL);
	if (status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));

	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &pInfo.ImageName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (hFile == INVALID_HANDLE_VALUE && status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	dwResult = GetFinalPathNameByHandle(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
	if (dwResult == 0) {
		goto CleanUp;
	}
	else if (dwResult >= _countof(lpszFilePath)) {
		goto CleanUp;
	}

	wcstok_s(lpszFilePath, L"\\", &pwszPath);

	swprintf_s(chBuffer, _countof(chBuffer), L"    Path:        %s\n", pwszPath);
	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		goto CleanUp;
	}

	RtlZeroMemory(chBuffer, _countof(chBuffer));

	if (GetBinaryType(pwszPath, &dwBinaryType)) {
		if (dwBinaryType == SCS_64BIT_BINARY) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    ImageType:   64-bit\n");
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
		else {
			swprintf_s(chBuffer, _countof(chBuffer), L"    ImageType:   32-bit\n");
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
	}

	DWORD dwHandle;
	dwLen = GetFileVersionInfoSize(pwszPath, &dwHandle);
	if (!dwLen) {
		goto CleanUp;
	}

	lpVerInfo = (PBYTE)GlobalAlloc(GPTR, dwLen);
	if (!GetFileVersionInfo(pwszPath, dwHandle, dwLen, lpVerInfo)) {
		goto CleanUp;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	UINT uLen;
	if (VerQueryValue(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
		swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

		wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\StringFileInfo\\");
		wcscat_s(wcCompanyName, _countof(wcCompanyName), wcCodePage);
		wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\CompanyName");

		wcscat_s(wcDescription, _countof(wcDescription), L"\\StringFileInfo\\");
		wcscat_s(wcDescription, _countof(wcDescription), wcCodePage);
		wcscat_s(wcDescription, _countof(wcDescription), L"\\FileDescription");

		wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\StringFileInfo\\");
		wcscat_s(wcProductVersion, _countof(wcProductVersion), wcCodePage);
		wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\ProductVersion");

		if (VerQueryValue(lpVerInfo, wcCompanyName, (void **)&lpCompany, &uLen)) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    CompanyName: %ls\n", lpCompany);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
		if (VerQueryValue(lpVerInfo, wcDescription, (void **)&lpDescription, &uLen)) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    Description: %ls\n", lpDescription);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}
		if (VerQueryValue(lpVerInfo, wcProductVersion, (void **)&lpProductVersion, &uLen)) {
			swprintf_s(chBuffer, _countof(chBuffer), L"    Version:     %ls\n", lpProductVersion);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));
		}

#pragma warning( push )
#pragma warning( disable : 4311 )		//C4311: 'type cast': pointer truncation from 'HANDLE' to 'DWORD'
#pragma warning( disable : 4302 )		//C4302: 'type cast': truncation from 'HANDLE' to 'DWORD'
		EnumSecurityProc(lpCompany, lpDescription, (DWORD)ProcessId);

#pragma warning( pop )
	}

CleanUp:

	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	if (pInfo.ImageName.Buffer != NULL) {
		free(pInfo.ImageName.Buffer);
	}

	if (lpVerInfo != NULL) {
		GlobalFree(lpVerInfo);
	}
	else {
		return FALSE;
	}

	return TRUE;
}

BOOL EnumKernel(IN LPSTREAM lpStream) {
	HANDLE hFile = NULL;
	LPVOID pBuffer = NULL;
	SIZE_T uSize = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	LPWSTR lpwKernelPath = NULL;
	HRESULT hr = S_OK;
	WCHAR lpszFilePath[MAX_PATH] = { 0 };
	DWORD dwLen = 0;
	LPWSTR pwszPath = NULL;
	WCHAR chBuffer[MAX_BUF] = { 0 };
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	PBYTE lpVerInfo = NULL;
	WCHAR wcCodePage[MAX_PATH] = { 0 };
	WCHAR wcCompanyName[MAX_PATH] = { 0 };
	WCHAR wcDescription[MAX_PATH] = { 0 };
	WCHAR wcProductVersion[MAX_PATH] = { 0 };
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;
	DWORD dwWritten = 0;

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
	if (!(status == STATUS_INFO_LENGTH_MISMATCH)) {
		goto CleanUp;
	}

	uSize = uReturnLength;
	status = NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	status = NtQuerySystemInformation(SystemModuleInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	kernelBase = pModuleInfo->Module[0].ImageBase;
	kernelImage = pModuleInfo->Module[0].FullPathName;

	lpwKernelPath = Utf8ToUtf16((LPSTR)pModuleInfo->Module[0].FullPathName);
	if (lpwKernelPath != NULL) {
		UNICODE_STRING uKernel;
		RtlInitUnicodeString(&uKernel, lpwKernelPath);

		IO_STATUS_BLOCK IoStatusBlock;
		ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));

		OBJECT_ATTRIBUTES FileObjectAttributes;
		InitializeObjectAttributes(&FileObjectAttributes, &uKernel, OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS Status = NtCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &FileObjectAttributes, &IoStatusBlock, 0,
			0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (hFile == INVALID_HANDLE_VALUE && status != STATUS_SUCCESS) {
			goto CleanUp;
		}

		DWORD dwResult = GetFinalPathNameByHandle(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
		if (dwResult == 0) {
			goto CleanUp;
		}
		else if (dwResult >= _countof(lpszFilePath)) {
			goto CleanUp;
		}

		wcstok_s(lpszFilePath, L"\\", &pwszPath);

		swprintf_s(chBuffer, _countof(chBuffer), L"    Path:        %s\n", pwszPath);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		if (GetBinaryType(pwszPath, &dwBinaryType)) {
			if (dwBinaryType == SCS_64BIT_BINARY) {
				swprintf_s(chBuffer, _countof(chBuffer), L"    ImageType:   64-bit\n");
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
			}
			else {
				swprintf_s(chBuffer, _countof(chBuffer), L"    ImageType:   32-bit\n");
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
			}
		}

		DWORD dwHandle;
		dwLen = GetFileVersionInfoSize(pwszPath, &dwHandle);
		if (!dwLen) {
			goto CleanUp;
		}

		lpVerInfo = (PBYTE)GlobalAlloc(GPTR, dwLen);
		if (!GetFileVersionInfo(pwszPath, dwHandle, dwLen, lpVerInfo)) {
			goto CleanUp;
		}

		struct LANGANDCODEPAGE {
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		UINT uLen;
		if (VerQueryValue(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
			swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

			wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\StringFileInfo\\");
			wcscat_s(wcCompanyName, _countof(wcCompanyName), wcCodePage);
			wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\CompanyName");

			wcscat_s(wcDescription, _countof(wcDescription), L"\\StringFileInfo\\");
			wcscat_s(wcDescription, _countof(wcDescription), wcCodePage);
			wcscat_s(wcDescription, _countof(wcDescription), L"\\FileDescription");

			wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\StringFileInfo\\");
			wcscat_s(wcProductVersion, _countof(wcProductVersion), wcCodePage);
			wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\ProductVersion");

			if (VerQueryValue(lpVerInfo, wcCompanyName, (void **)&lpCompany, &uLen)) {
				swprintf_s(chBuffer, _countof(chBuffer), L"    CompanyName: %ls\n", lpCompany);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
			}
			if (VerQueryValue(lpVerInfo, wcDescription, (void **)&lpDescription, &uLen)) {
				swprintf_s(chBuffer, _countof(chBuffer), L"    Description: %ls\n", lpDescription);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
			}
			if (VerQueryValue(lpVerInfo, wcProductVersion, (void **)&lpProductVersion, &uLen)) {
				swprintf_s(chBuffer, _countof(chBuffer), L"    Version:     %ls\n", lpProductVersion);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
			}
		}
	}
	else {
		swprintf_s(chBuffer, _countof(chBuffer), L"    KernelImage: %hs \n", kernelImage);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));

		swprintf_s(chBuffer, _countof(chBuffer), L"    BaseAddress: 0x%p \n", kernelBase);
		if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}

		RtlZeroMemory(chBuffer, _countof(chBuffer));
	}

CleanUp:

	if (pBuffer == NULL) {
		status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
	}

	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	if (lpVerInfo != NULL) {
		GlobalFree(lpVerInfo);
	}
	else {
		return FALSE;
	}

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

			BOOL bExtended = TRUE;
			HRESULT hr = S_OK;
			NTSTATUS status;
			LPSTREAM lpStream = NULL;
			DWORD dwWritten = 0;
			STATSTG ssStreamData = { 0 };
			SIZE_T cbSize = 0;
			ULONG cbRead = 0;
			LARGE_INTEGER pos;
			WCHAR chBuffer[MAX_BUF] = { 0 };
			LPVOID pBuffer = NULL;
			ULONG uReturnLength = 0;
			SIZE_T uSize = 0;
			PSYSTEM_PROCESSES pProcInfo = NULL;
			LPWSTR lpwOutput = NULL;
			FILETIME ftCreate;
			SYSTEMTIME stUTC, stLocal;
			DWORD SessionID;
			DWORD dwTotalProc = 0, dwLowProc = 0, dwMediumProc = 0, dwHighProc = 0, dwSystemProc = 0;

			WCHAR wcLsass[MAX_PATH] = { 0 };
			WCHAR wcWinlogon[MAX_PATH] = { 0 };
			WCHAR wcSecSystem[MAX_PATH] = { 0 };

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
				exit(1);
			}

			_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
				GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");
			if (RtlEqualUnicodeString == NULL) {
				exit(1);
			}

			// Create memory Stream
			if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, &lpStream))) {
				exit(1);
			}

			status = NtQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
			if (!(status == STATUS_INFO_LENGTH_MISMATCH)) {
				goto CleanUp;
			}

			uSize = uReturnLength;
			status = NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
			if (status != STATUS_SUCCESS) {
				goto CleanUp;
			}

			status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
			if (status != STATUS_SUCCESS) {
				status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
				goto CleanUp;
			}

			if (IsElevated()) {
				SetDebugPrivilege();
			}

			for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
				pSecProducts[i] = (PSECPROD)calloc(1, sizeof(SECPROD));
			}

			UNICODE_STRING uLsass;
			UNICODE_STRING uWinlogon;
			UNICODE_STRING uSecSystem;
			wcscpy_s(wcLsass, _countof(wcLsass), L"lsass.exe");
			wcscpy_s(wcWinlogon, _countof(wcWinlogon), L"winlogon.exe");
			wcscpy_s(wcSecSystem, _countof(wcSecSystem), L"Secure System");

			RtlInitUnicodeString(&uLsass, (PCWSTR)wcLsass);
			RtlInitUnicodeString(&uWinlogon, (PCWSTR)wcWinlogon);
			RtlInitUnicodeString(&uSecSystem, (PCWSTR)wcSecSystem);

#pragma warning( push )
#pragma warning( disable : 4311 )		//C4311: 'type cast': pointer truncation from 'HANDLE' to 'DWORD'
#pragma warning( disable : 4302 )		//C4302: 'type cast': truncation from 'HANDLE' to 'DWORD'

			swprintf_s(chBuffer, _countof(chBuffer), L"[PStoolsStart]\n\n[V] Output from Outflank PSX version %ls\n", lpwPsXVersion);
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));

			pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
			do {
				pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

				swprintf_s(chBuffer, _countof(chBuffer), L"\n[I] ProcessName: %wZ\n", &pProcInfo->ProcessName);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));

				swprintf_s(chBuffer, _countof(chBuffer), L"    ProcessID:   %d\n", (DWORD)pProcInfo->ProcessId);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));

				swprintf_s(chBuffer, _countof(chBuffer), L"    PPID:        %d ", (DWORD)pProcInfo->InheritedFromProcessId);
				if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
					goto CleanUp;
				}

				RtlZeroMemory(chBuffer, _countof(chBuffer));
				dwTotalProc++;

				PSYSTEM_PROCESSES pParentInfo = (PSYSTEM_PROCESSES)pBuffer;
				do {
					pParentInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pParentInfo) + pParentInfo->NextEntryDelta);

					if ((DWORD)pParentInfo->ProcessId == (DWORD)pProcInfo->InheritedFromProcessId) {
						swprintf_s(chBuffer, _countof(chBuffer), L"(%wZ)\n", &pParentInfo->ProcessName);
						if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
							goto CleanUp;
						}

						RtlZeroMemory(chBuffer, _countof(chBuffer));
						break;
					}
					else if (pParentInfo->NextEntryDelta == 0) {
						swprintf_s(chBuffer, _countof(chBuffer), L"(Non-existent process)\n");
						if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
							goto CleanUp;
						}

						RtlZeroMemory(chBuffer, _countof(chBuffer));
						break;
					}

				} while (pParentInfo);

				ftCreate.dwLowDateTime = pProcInfo->CreateTime.LowPart;
				ftCreate.dwHighDateTime = pProcInfo->CreateTime.HighPart;

				// Convert the Createtime to local time.
				FileTimeToSystemTime(&ftCreate, &stUTC);
				if (SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
					swprintf_s(chBuffer, _countof(chBuffer), L"    CreateTime:  %02d/%02d/%d %02d:%02d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute);
					if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
						goto CleanUp;
					}

					RtlZeroMemory(chBuffer, _countof(chBuffer));
				}

				if (ProcessIdToSessionId((DWORD)pProcInfo->ProcessId, &SessionID)) {

					swprintf_s(chBuffer, _countof(chBuffer), L"    SessionID:   %d\n", SessionID);
					if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
						goto CleanUp;
					}

					RtlZeroMemory(chBuffer, _countof(chBuffer));
				}

				// Exclude ProcessHandle on Lsass and WinLogon (Sysmon will log this). 
				if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
					continue;
				}
				if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uWinlogon, TRUE)) {
					continue;
				}
				if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uSecSystem, TRUE)) {
					continue;
				}

				if ((DWORD)pProcInfo->ProcessId == 4) {
					EnumKernel(lpStream);
				}
				else {
					EnumFileProperties(pProcInfo->ProcessId, lpStream);
				}

				//Psx (Extended Process Info)
				if (bExtended) {
					HANDLE hProcess = NULL;
					OBJECT_ATTRIBUTES ObjectAttributes;
					InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
					CLIENT_ID uPid = { 0 };

					uPid.UniqueProcess = pProcInfo->ProcessId;
					uPid.UniqueThread = (HANDLE)0;

					status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
					if (hProcess != NULL) {
						LPWSTR lpwProcUser = GetProcessUser(hProcess, FALSE, TRUE, TRUE);
						if (lpwProcUser != NULL) {
							swprintf_s(chBuffer, _countof(chBuffer), L"    UserName:    %s\n", lpwProcUser);
							if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
								goto CleanUp;
							}

							RtlZeroMemory(chBuffer, _countof(chBuffer));
							free(lpwProcUser);
						}

						DWORD dwIntegrityLevel = IntegrityLevel(hProcess);
						if (dwIntegrityLevel == LowIntegrity) {
							swprintf_s(chBuffer, _countof(chBuffer), L"    Integrity:   Low\n");
							if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
								goto CleanUp;
							}

							RtlZeroMemory(chBuffer, _countof(chBuffer));
							dwLowProc++;
						}
						else if (dwIntegrityLevel == MediumIntegrity) {
							swprintf_s(chBuffer, _countof(chBuffer), L"    Integrity:   Medium\n");
							if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
								goto CleanUp;
							}

							RtlZeroMemory(chBuffer, _countof(chBuffer));
							dwMediumProc++;
						}
						else if (dwIntegrityLevel == HighIntegrity) {
							swprintf_s(chBuffer, _countof(chBuffer), L"    Integrity:   High\n");
							if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
								goto CleanUp;
							}

							RtlZeroMemory(chBuffer, _countof(chBuffer));
							dwHighProc++;
						}
						else if (dwIntegrityLevel == SystemIntegrity) {
							swprintf_s(chBuffer, _countof(chBuffer), L"    Integrity:   System\n");
							if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
								goto CleanUp;
							}

							RtlZeroMemory(chBuffer, _countof(chBuffer));
							dwSystemProc++;
						}

						EnumPeb(hProcess, lpStream);

						// Close the Process Handle
						CloseHandle(hProcess);
					}
				}

				if (pProcInfo->NextEntryDelta == 0) {
					break;
				}

			} while (pProcInfo);

#pragma warning( pop )

			PrintSummary(lpStream, dwTotalProc, dwLowProc, dwMediumProc, dwHighProc, dwSystemProc);

			swprintf_s(chBuffer, _countof(chBuffer), L"[PStoolsEnd]\n");
			if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
				goto CleanUp;
			}

			RtlZeroMemory(chBuffer, _countof(chBuffer));

			// Allocate enough memory for the Output
			if (FAILED(lpStream->Stat(&ssStreamData, STATFLAG_NONAME))) {
				goto CleanUp;
			}

			cbSize = ssStreamData.cbSize.LowPart;

			lpwOutput = (LPWSTR)calloc(cbSize + 1, sizeof(WCHAR));

			// Rewind Memory Stream
			pos.QuadPart = 0;
			if (FAILED(lpStream->Seek(pos, STREAM_SEEK_SET, NULL))) {
				free(lpwOutput);
				goto CleanUp;
			}

			// Write Stream to Output string
			if (FAILED(lpStream->Read(lpwOutput, (ULONG)cbSize, &cbRead))) {
				free(lpwOutput);
				goto CleanUp;
			}

			if (lpwOutput != NULL) {
				wprintf(L"%ls", lpwOutput);
			}

		CleanUp:
			if (lpStream) {
				lpStream->Release();
				lpStream = NULL;
			}
			else {
				ExitProcess(0);
			}

			if (pBuffer) {
				NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
			}
			else {
				ExitProcess(0);
			}

			if (pSecProducts[0] != NULL) {
				for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
					free(pSecProducts[i]);
				}
				dwNonMSProc = 0;
				dwMSProc = 0;
				dwSecProcCount = 0;
			}
			else {
				ExitProcess(0);
			}
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
