#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <shlwapi.h>
#include "ReflectiveLoader.h"
#include "psw.h"

#pragma comment(lib, "Shlwapi.lib")

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	DWORD dwProcessId = 0;
	WCHAR chWindowTitle[MAX_PATH];

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return TRUE;
	}

	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		return TRUE;
	}

	_NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
	if (NtFreeVirtualMemory == NULL) {
		return TRUE;
	}

	if (!hWnd) {
		return TRUE;
	}

	if (!IsWindowVisible(hWnd)) {
		return TRUE;
	}

	if (!SendMessage(hWnd, WM_GETTEXT, sizeof(chWindowTitle), (LPARAM)chWindowTitle)) {
		return TRUE;
	}

	GetWindowThreadProcessId(hWnd, &dwProcessId);

	if (dwProcessId != 0) {
		ULONG uReturnLength = 0;
		NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
		if (!status == 0xc0000004) {
			return TRUE;
		}

		LPVOID pBuffer = NULL;
		SIZE_T uSize = uReturnLength;
		status = NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			return TRUE;
		}

		status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
		if (status != STATUS_SUCCESS) {
			return TRUE;
		}

		PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
		do {
			pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

			if (pProcInfo->ProcessId == dwProcessId) {
				wprintf(L"\n[+] ProcessName:\t %wZ\n", &pProcInfo->ProcessName);
				wprintf(L"    ProcessID:\t %d\n", dwProcessId);
				wprintf(L"    WindowTitle:\t %ls\n", chWindowTitle);
				break;
			}
			else if (pProcInfo->NextEntryDelta == 0) {
				wprintf(L"\n[!] ProcessID not found.\n");
				break;
			}

		} while (pProcInfo);

		status = NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
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
			EnumWindows(EnumWindowsProc, (LPARAM)NULL);
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
