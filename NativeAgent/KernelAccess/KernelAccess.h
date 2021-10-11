#include "interface.h"
#include <vector>

class KernelAccess
{
public:
    KernelAccess();

    KernelAccess(const KernelAccess& another) = delete;

    ~KernelAccess();

    void* AllocateRemoteMemory(DWORD pid, void* addr, DWORD length, DWORD protect);

    void ReadProcessMemory(DWORD pid, void* addr, DWORD length, std::vector<BYTE>& out);

    DWORD WriteProcessMemory(DWORD pid, void* addr, const std::vector<BYTE>& data);

    DWORD CreateProcessThread(DWORD pid, void* addr, void* param, DWORD flag);

private:
    HANDLE driverHandle = NULL;
};