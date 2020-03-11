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

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Shlwapi.lib")

PSECPROD pSecProducts[64] = { 0 };
DWORD dwMSMod = 0, dwNonMSMod = 0, dwSecModCount = 0, dwTotalMod = 0;

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

BOOL OSInfo() {
	OSVERSIONINFOEXW osInfo;

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	osInfo.dwOSVersionInfoSize = sizeof(osInfo);
	RtlGetVersion(&osInfo);

	wprintf(L"\n[+] Windows OS Version: %u.%u build %u\n", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);

	return TRUE;
}

void EnumSecurityProc(LPWSTR lpCompany, LPWSTR lpDescription) {
	pSecProducts[dwSecModCount] = (PSECPROD)calloc(1, sizeof(SECPROD));

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
			pSecProducts[dwSecModCount]->lpCompany = lpCompany;
			pSecProducts[dwSecModCount]->lpDescription = lpDescription;
			dwSecModCount++;
		}
	}

	//Windows Defender (ATP)
	if (StrStrIW(lpDescription, L"Antimalware") || StrStrIW(lpDescription, L"Windows Defender")) {
		pSecProducts[dwSecModCount]->lpCompany = lpCompany;
		pSecProducts[dwSecModCount]->lpDescription = lpDescription;
		dwSecModCount++;
	}

	//Microsoft
	if (StrStrIW(lpCompany, L"Microsoft")) {
		dwMSMod++;
	}
	else {
		dwNonMSMod++;
	}

	return;
}

BOOL EnumKernel() {
	LPVOID moduleBase = NULL;
	LPWSTR lpwModulePath = NULL;
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
	dwTotalMod = pModuleInfo->NumberOfModules;

	for (DWORD i = 0; i < pModuleInfo->NumberOfModules; i++) {
		lpwModulePath = Utf8toUtf16(pModuleInfo->Module[i].FullPathName);
		if (lpwModulePath != NULL) {
			UNICODE_STRING uKernel;
			RtlInitUnicodeString(&uKernel, lpwModulePath);

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

			if (hFile == NULL) {
				continue;
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

			if (i == 0) {
				wprintf(L"    Path:\t %s\n", pwszPath);
			}
			else {
				wprintf(L"[+] ModulePath:\t %s\n", pwszPath);
			}

			moduleBase = pModuleInfo->Module[i].ImageBase;
			wprintf(L"    BaseAddress:\t 0x%p \n", moduleBase);

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
					wprintf(L"    Version:\t %s\n\n", lpProductVersion);
				}

				EnumSecurityProc(lpCompany, lpDescription);
			}

			CloseHandle(hFile);
		}
	}

	status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

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

			if (!OSInfo()) {
				wprintf(L"\n[!] OSInfo Failed!\n\n");
			}

			PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
			do {
				pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

				wprintf(L"\n[+] ProcessName:\t %wZ\n", &pProcInfo->ProcessName);
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
					break;
				}

				if (pProcInfo->NextEntryDelta == 0) {
					break;
				}

			} while (pProcInfo);

			status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

			if (dwSecModCount > 0) {
				wprintf(L"--------------------------------------------------------------------\n");
				wprintf(L"[!] Security products found:\n");
				for (DWORD i = 0; i < dwSecModCount; i++) {
					wprintf(L"    Vendor:\t %ls\n", pSecProducts[i]->lpCompany);
					wprintf(L"    Product:\t %ls\n\n", pSecProducts[i]->lpDescription);
				}
			}

			wprintf(L"--------------------------------------------------------------------\n");
			wprintf(L"[I] Kernel Module summary:\n");
			wprintf(L"    Microsoft kernel modules: %d\n", dwMSMod);
			wprintf(L"    Non Microsoft modules:    %d\n\n", dwNonMSMod);

			wprintf(L"    Total active modules:     %d\n\n", dwTotalMod);
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
