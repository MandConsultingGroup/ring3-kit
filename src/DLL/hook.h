#pragma once
#ifndef __HOOK_H
#define __HOOK_H
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

#define DEF_ERROR_CODE_STANDARD -1
#define DEF_SUCCESS_CODE_STANDARD 0x00

#pragma region NtDllPreDefs
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
typedef struct _NT_SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} NT_SYSTEM_PROCESS_INFORMATION, *PNT_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(__stdcall *PNT_QUERY_SYSTEM_INFORMATION) (
	__in		SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout		PVOID SystemInformation,
	__in		ULONG SystemInformationLength,
	__out_opt	PULONG ReturnLength
	);

namespace Hook {
	PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = reinterpret_cast<PNT_QUERY_SYSTEM_INFORMATION>(GetProcAddress(
		GetModuleHandle("ntdll"), "NtQuerySystemInformation"));

	NTSTATUS __stdcall HookedNtQuerySystemInformation(
		__in		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		__inout		PVOID SystemInformation,
		__in		ULONG SystemInformationLength,
		__out_opt	PULONG ReturnLength
	);

	void Win32ExecuteHook();

}

#endif 