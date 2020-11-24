#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include <Winver.h>
#include <shlwapi.h>
#include "ReflectiveLoader.h"
#include "psk.h"

#define MAX_SEC_PRD 20

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Shlwapi.lib")

PSECPROD pSecProducts[MAX_SEC_PRD] = { 0 };
DWORD dwMSMod = 0, dwNonMSMod = 0, dwSecModCount = 0, dwTotalMod = 0;

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

BOOL OSInfo() {
	OSVERSIONINFOEXW osInfo;

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	osInfo.dwOSVersionInfoSize = sizeof(osInfo);
	NTSTATUS status = RtlGetVersion(&osInfo);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	wprintf(L"\n[+] Windows OS Version: %u.%u build %u\n", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);

	return TRUE;
}

BOOL EnumSecurityProc(IN LPWSTR lpCompany, IN LPWSTR lpDescription) {
	LPWSTR pwszCompany[26];
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
	for (DWORD i = 0; i < dwSize && dwSecModCount < MAX_SEC_PRD; i++) {
		if (StrStrIW(lpCompany, pwszCompany[i])) {
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcCompany, lpCompany, wcslen(lpCompany) * sizeof(WCHAR));
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcDescription, lpDescription, wcslen(lpDescription) * sizeof(WCHAR));
			dwSecModCount++;
		}
	}

	if (dwSecModCount < MAX_SEC_PRD) {
		//Windows Defender (ATP)
		if (StrStrIW(lpDescription, L"Antimalware") || StrStrIW(lpDescription, L"Windows Defender")) {
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcCompany, lpCompany, wcslen(lpCompany) * sizeof(WCHAR));
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcDescription, lpDescription, wcslen(lpDescription) * sizeof(WCHAR));
			dwSecModCount++;
		}
	}

	if (dwSecModCount < MAX_SEC_PRD) {
		//Carbon Black
		if (StrStrIW(lpDescription, L"Carbon Black")) {
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcCompany, lpCompany, wcslen(lpCompany) * sizeof(WCHAR));
			RtlCopyMemory(pSecProducts[dwSecModCount]->wcDescription, lpDescription, wcslen(lpDescription) * sizeof(WCHAR));
			dwSecModCount++;
		}
	}

	//Microsoft
	if (StrStrIW(lpCompany, L"Microsoft")) {
		dwMSMod++;
	}
	else {
		dwNonMSMod++;
	}

	RtlZeroMemory(pwszCompany, sizeof(pwszCompany));

	return TRUE;
}

BOOL EnumKernel() {
	BOOL bResult = TRUE;
	HANDLE hFile = NULL;
	LPVOID moduleBase = NULL;
	LPWSTR lpwModulePath = NULL;
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	PBYTE lpVerInfo = NULL;
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;

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
		bResult = FALSE;
		goto CleanUp;
	}

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	dwTotalMod = pModuleInfo->NumberOfModules;

	for (DWORD i = 0; i < pModuleInfo->NumberOfModules; i++) {
		lpwModulePath = Utf8ToUtf16(pModuleInfo->Module[i].FullPathName);
		if (lpwModulePath != NULL) {
			UNICODE_STRING uKernel;
			RtlInitUnicodeString(&uKernel, lpwModulePath);

			IO_STATUS_BLOCK IoStatusBlock;
			ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
			OBJECT_ATTRIBUTES FileObjectAttributes;
			InitializeObjectAttributes(&FileObjectAttributes, &uKernel, OBJ_CASE_INSENSITIVE, NULL, NULL);

			NTSTATUS Status = NtCreateFile(&hFile, (GENERIC_READ | SYNCHRONIZE), &FileObjectAttributes, &IoStatusBlock, 0,
				0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

			if (hFile == INVALID_HANDLE_VALUE) {
				bResult = FALSE;
				goto CleanUp;
			}

			if (hFile == NULL) {
				continue;
			}

			WCHAR lpszFilePath[MAX_PATH + 1];
			DWORD dwResult = GetFinalPathNameByHandle(hFile, lpszFilePath, _countof(lpszFilePath) - 1, VOLUME_NAME_DOS);
			if (dwResult == 0) {
				bResult = FALSE;
				goto CleanUp;
			}
			else if (dwResult >= _countof(lpszFilePath)) {
				bResult = FALSE;
				goto CleanUp;
			}

			LPWSTR pwszPath = NULL;
			wcstok_s(lpszFilePath, L"\\", &pwszPath);

			if (i == 0) {
				wprintf(L"    Path:          %s\n", pwszPath);
			}
			else {
				wprintf(L"[+] ModulePath:    %s\n", pwszPath);
			}

			moduleBase = pModuleInfo->Module[i].ImageBase;
			wprintf(L"    BaseAddress:   0x%p \n", moduleBase);

			if (GetBinaryType(pwszPath, &dwBinaryType)) {
				if (dwBinaryType == SCS_64BIT_BINARY) {
					wprintf(L"    ImageType:     64-bit\n");
				}
				else {
					wprintf(L"    ImageType:     32-bit\n");
				}
			}

			DWORD dwHandle;
			DWORD dwLen = GetFileVersionInfoSize(pwszPath, &dwHandle);
			if (!dwLen) {
				bResult = FALSE;
				goto CleanUp;
			}

			lpVerInfo = (PBYTE)GlobalAlloc(GPTR, dwLen);
			if (!GetFileVersionInfo(pwszPath, dwHandle, dwLen, lpVerInfo)) {
				bResult = FALSE;
				goto CleanUp;
			}

			struct LANGANDCODEPAGE {
				WORD wLanguage;
				WORD wCodePage;
			} *lpTranslate;

			WCHAR wcCodePage[MAX_PATH] = { 0 };
			WCHAR wcCompanyName[MAX_PATH] = { 0 };
			WCHAR wcDescription[MAX_PATH] = { 0 };
			WCHAR wcProductVersion[MAX_PATH] = { 0 };

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
					wprintf(L"    CompanyName:   %ls\n", lpCompany);
				}
				if (VerQueryValue(lpVerInfo, wcDescription, (void **)&lpDescription, &uLen)) {
					wprintf(L"    Description:   %ls\n", lpDescription);
				}
				if (VerQueryValue(lpVerInfo, wcProductVersion, (void **)&lpProductVersion, &uLen)) {
					wprintf(L"    Version:       %ls\n\n", lpProductVersion);
				}

				EnumSecurityProc(lpCompany, lpDescription);
			}

			if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
				CloseHandle(hFile);
			}

			if (lpVerInfo != NULL) {
				GlobalFree(lpVerInfo);
			}

			if (lpwModulePath != NULL) {
				free(lpwModulePath);
			}
		}
	}

CleanUp:

	if (pBuffer) {
		status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
	}

	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	if (lpVerInfo != NULL) {
		GlobalFree(lpVerInfo);
	}

	if (lpwModulePath != NULL) {
		free(lpwModulePath);
	}

	return bResult;
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

			ULONG uReturnLength = 0;
			NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
			if (!(status == STATUS_INFO_LENGTH_MISMATCH)) {
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

			for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
				pSecProducts[i] = (PSECPROD)calloc(1, sizeof(SECPROD));
			}

			if (!OSInfo()) {
				wprintf(L"\n[!] OSInfo Failed!\n\n");
			}

			PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
			do {
				pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

				wprintf(L"\n[+] ProcessName:   %wZ\n", &pProcInfo->ProcessName);
				wprintf(L"    ProcessID:     %d\n", (DWORD)pProcInfo->ProcessId);
				wprintf(L"    PPID:          %d ", (DWORD)pProcInfo->InheritedFromProcessId);

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
					wprintf(L"    CreateTime:    %02d/%02d/%d %02d:%02d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute);
				}

				if (ProcessIdToSessionId((DWORD)pProcInfo->ProcessId, &SessionID)) {
					wprintf(L"    SessionID:     %d\n", SessionID);
				}

				if ((DWORD)pProcInfo->ProcessId == 4) {
					EnumKernel();
					break;
				}

				if (pProcInfo->NextEntryDelta == 0) {
					break;
				}

			} while (pProcInfo);

			if (dwSecModCount > 0) {
				wprintf(L"--------------------------------------------------------------------\n");
				wprintf(L"[!] Security products found:\n");
				for (DWORD i = 0; i < dwSecModCount; i++) {
					wprintf(L"    Vendor:        %ls\n", pSecProducts[i]->wcCompany);
					wprintf(L"    Product:       %ls\n\n", pSecProducts[i]->wcDescription);
				}
			}

			wprintf(L"--------------------------------------------------------------------\n");
			wprintf(L"[I] Kernel Module summary:\n");
			wprintf(L"    Microsoft kernel modules: %d\n", dwMSMod);
			wprintf(L"    Non Microsoft modules:    %d\n\n", dwNonMSMod);

			wprintf(L"    Total active modules:     %d\n\n", dwTotalMod);

			if (pBuffer != NULL) {
				NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
			}

			if (pSecProducts[0] != NULL) {
				for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
					free(pSecProducts[i]);
				}
				dwNonMSMod = 0;
				dwMSMod = 0;
				dwSecModCount = 0;
			}

			if (pwszParams != NULL) {
				free(pwszParams);
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
