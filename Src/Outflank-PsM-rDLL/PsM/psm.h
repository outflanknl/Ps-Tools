#pragma once
#pragma warning(disable: 4311)

#include <Windows.h>

#define STATUS_SUCCESS 0
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define MAX_NAME 256
typedef LONG KPRIORITY;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_SHARE_READ 0x00000001
#define FILE_OPEN 0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemProcessIdInformation = 88
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA2 {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// Partial PEB
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY2 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef void (WINAPI * PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);


typedef NTSTATUS(NTAPI *_NtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

typedef NTSTATUS(NTAPI *_NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI *_NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	IN OUT PSIZE_T RegionSize,
	ULONG FreeType
	);

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_NtOpenProcessToken)(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle
	);

typedef NTSTATUS(NTAPI *_NtQueryInformationToken)(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_NtAdjustPrivilegesToken)(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES TokenPrivileges,
	IN ULONG PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
	OUT PULONG RequiredLength OPTIONAL
	);

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS(NTAPI *_NtReadVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI *_NtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);

typedef PWSTR(NTAPI *_RtlIpv4AddressToStringW)(
	struct in_addr *Addr,
	PWSTR S
	);

typedef PWSTR(NTAPI *_RtlIpv6AddressToStringW)(
	struct in6_addr *Addr,
	PWSTR S
	);
