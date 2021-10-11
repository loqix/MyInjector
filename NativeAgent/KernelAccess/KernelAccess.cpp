#include "KernelAccess.h"
#include "../Common.h"

KernelAccess::KernelAccess()
{
    driverHandle = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == driverHandle)
    {
        Common::ThrowException("Cannot open driver. Is the driver correctly loaded?");
    }
}

KernelAccess::~KernelAccess()
{
    CloseHandle(driverHandle);
}

void* KernelAccess::AllocateRemoteMemory(DWORD pid, void* addr, DWORD length, DWORD protect)
{
    KCProtocols::REQUEST_ALLOC_PROCESS_MEM request = {};
    KCProtocols::RESPONSE_ALLOC_PROCESS_MEM response = {};
    request.addr = (UINT64)addr;
    request.length = (UINT32)length;
    request.isFree = false;
    request.pid = pid;
    request.protect = protect;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(driverHandle, CC_ALLOC_PROCESS_MEM, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        Common::ThrowException("Allocate memory failed.");
    }
    return (void*)response.base;
}

void KernelAccess::ReadProcessMemory(DWORD pid, void* addr, DWORD length, std::vector<BYTE>& out)
{
    KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
    KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)malloc(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length);
    free(response);
}
