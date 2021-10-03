#pragma once
#include <windows.h>

struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    PVOID Callback;
};

// Since Windows 10
struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_EX
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

#define ProcessInstrumentationCallback 40


NTSTATUS(NTAPI* NtSetInformationProcess)(
    IN HANDLE               ProcessHandle,
    IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
    IN PVOID                ProcessInformation,
    IN ULONG                ProcessInformationLength) = (decltype(NtSetInformationProcess))GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtSetInformationProcess");





