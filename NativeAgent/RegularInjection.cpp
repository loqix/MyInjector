#include <windows.h>
#include "RegularInjection.h"
#include <memory>
#include <iostream>
#include "Common.h"
#include "UndocumentedData.h"

class IProcessAccess
{
public:
    virtual void ReadMemory(void* addr, SIZE_T len, std::vector<BYTE>& dataRead) = 0;

    virtual void WriteMemory(void* addr, const std::vector<BYTE>& data, SIZE_T& bytesWritten) = 0;

    /// <summary>
    /// Allocate memory in target process's context
    /// </summary>
    /// <param name="addr"></param>
    /// <param name="len"></param>
    /// <param name="protect">example PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE</param>
    /// <returns></returns>
    virtual void* AllocateMemory(void* addr, SIZE_T len, DWORD protect) = 0;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="addr">Address of start routine</param>
    /// <param name="param">Start routine's parameter</param>
    /// <param name="flag">Example: CREATE_SUSPENDED</param>
    /// <param name="threadId"></param>
    /// <returns>Handle to the thread</returns>
    virtual HANDLE CreateThread(void* addr, void* param, DWORD flag, DWORD& threadId) = 0;

    virtual void SetProcessInstrumentCallback(void* target) = 0;
};

class HandleProcessAccess : public IProcessAccess
{
public:
    virtual void ReadMemory(void* addr, SIZE_T len, std::vector<BYTE>& dataRead) override
    {
        dataRead.clear();
        SIZE_T bytesRead = 0;
        std::unique_ptr<BYTE> buffer = std::make_unique<BYTE>(len);
        if (!ReadProcessMemory(handle, addr, buffer.get(), len, &bytesRead))
        {
            Common::ThrowException("ReadProcessMemory() failed with %d.", GetLastError());
        }
        dataRead.assign(buffer.get(), buffer.get() + bytesRead);
    }

    virtual void WriteMemory(void* addr, const std::vector<BYTE>& data, SIZE_T& bytesWritten) override
    {
        if (!WriteProcessMemory(handle, addr, &data[0], data.size(), &bytesWritten))
        {
            Common::ThrowException("WriteProcessMemory() failed with %d.", GetLastError());
        }
    }

    virtual void* AllocateMemory(void* addr, SIZE_T len, DWORD protect) override
    {
        auto ret = VirtualAllocEx(handle, addr, len, MEM_COMMIT | MEM_RESERVE, protect);
        if (!ret)
        {
            Common::ThrowException("VirtualAllocEx() failed with %d.", GetLastError());
        }
        return ret;
    }

    virtual HANDLE CreateThread(void* addr, void* param, DWORD flag, DWORD& threadId) override
    {
        auto ret = CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)addr, param, flag, &threadId);
        if (!ret)
        {
            Common::ThrowException("CreateRemoteThread() failed with %d.", GetLastError());
        }
        return ret;
    }

    virtual void SetProcessInstrumentCallback(void* target)
    {
        if (Common::SetPrivilege(L"SeDebugPrivilege", true))
        {
            Common::Print("[+] DebugPrivilege set.");
        }
        else
        {
            Common::Print("[!] Set privilege failed(Did you run this program under administration right?)");
        }

#ifdef _WIN64
        bool is64 = true;
#else
        bool is64 = false;
#endif
        DWORD winVer = 0;
        Common::GetWindowsVersion(winVer);
        if (winVer >= 10)
        {
            PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_EX info = {};
            info.Callback = target;
            info.Version = is64 ? 0 : 1;
            auto ret = NtSetInformationProcess(handle, (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback, &info, sizeof(info));
            if (ret != 0)
            {
                Common::ThrowException("NtSetInformationProcess failed with %d, last error: %d", ret, GetLastError());
            }
        }
        else
        {
            PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = {};
            info.Callback = target;
            auto ret = NtSetInformationProcess(handle, (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback, &info, sizeof(info));
            if (ret != 0)
            {
                Common::ThrowException("NtSetInformationProcess failed with %d, last error: %d", ret, GetLastError());
            }
        }
    }

    HandleProcessAccess(HANDLE handle)
    {
        this->handle = handle;
    }

    HandleProcessAccess(const HandleProcessAccess& another) = delete;

    virtual ~HandleProcessAccess()
    {
        CloseHandle(handle);
    }

private:
    HANDLE handle = NULL;
};

class KernelProcessAccess : public IProcessAccess
{
public:
    virtual void ReadMemory(void* addr, SIZE_T len, std::vector<BYTE>& dataRead) override
    {
        return ;
    }

    virtual void WriteMemory(void* addr, const std::vector<BYTE>& data, SIZE_T& bytesWritten) override
    {
        return ;
    }

    virtual void* AllocateMemory(void* addr, SIZE_T len, DWORD protect) override
    {
        return NULL;
    }

    virtual HANDLE CreateThread(void* addr, void* param, DWORD flag, DWORD& threadId) override
    {
        return NULL;
    }

    virtual void SetProcessInstrumentCallback(void* target) override
    {
        return;
    }

    KernelProcessAccess()
    {
        ;
    }

private:
    
};

class IEntryPoint
{
public:
    virtual void* GetEntryPoint() = 0;

    virtual void* GetParameter() = 0;
};

class LoadLibraryEntryPoint : public IEntryPoint
{
public:
    virtual void Prepare(const std::wstring& dllPath)
    {
        // write dll path, in wide char, to target memory
        int dataSize = (dllPath.size() + 1) * sizeof(wchar_t);
        auto allocated = access->AllocateMemory(0, dataSize, PAGE_READWRITE);
        std::vector<BYTE> buffer((BYTE*)dllPath.c_str(), (BYTE*)dllPath.c_str() + dataSize);
        SIZE_T bytesWritten = 0;
        access->WriteMemory(allocated, buffer, bytesWritten);

        parameter = allocated;
        if (auto base = GetModuleHandleW(L"Kernel32"))
        {
            entrypoint = GetProcAddress(base, "LoadLibraryW");
        }
        if (!entrypoint)
        {
            Common::ThrowException("Cannot get the address of Kernel32.LoadLibraryW().");
        }
    }

    virtual void* GetEntryPoint() override
    {
        return entrypoint;
    }

    virtual void* GetParameter() override
    {
        return parameter;
    }

    LoadLibraryEntryPoint(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* entrypoint = NULL;
    void* parameter = NULL;
};

class LdrLoadDllEntryPoint : public IEntryPoint
{
public:
    virtual bool Prepare()
    {
        ;
    }

    virtual void* GetEntryPoint() override
    {
        ;
    }

    virtual void* GetParameter() override
    {
        ;
    }

    LdrLoadDllEntryPoint(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* entry_point = NULL;
    void* parameter = NULL;
};

class ManualLoadEntryPoint : public IEntryPoint
{
public:
    virtual bool Prepare()
    {
        ;
    }

    virtual void* GetEntryPoint() override
    {
        ;
    }

    virtual void* GetParameter() override
    {
        ;
    }

    ManualLoadEntryPoint(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* entry_point = NULL;
    void* parameter = NULL;
};

class IExecuter
{
public:
    virtual void Go() = 0;
};

class CreateRemoteThreadExecuter : public IExecuter
{
public:
    virtual void Go() override
    {
        DWORD threadId = 0;
        auto handle = access->CreateThread(startAddr, parameter, 0, threadId);
        if (WAIT_OBJECT_0 != WaitForSingleObject(handle, 5 * 1000)) // wait for 5 seconds for the LoadLibrary() call to return.
        {
            Common::Print("[!] New thread does not return in 5 seconds.");
        }
    }

    void Prepare(void* startAddr, void* parameter)
    {
        this->startAddr = startAddr;
        this->parameter = parameter;
    }

    CreateRemoteThreadExecuter(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* startAddr = NULL;
    void* parameter = NULL;
};

// See https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html
class InstrumentCallbackExecuter : public IExecuter
{
public:
    virtual void Go() override
    {
        access->SetProcessInstrumentCallback(realEntryPoint);
    }

    void Prepare(void* startAddr, void* parameter)
    {
        this->startAddr = startAddr;
        this->parameter = parameter;
        auto base = access->AllocateMemory(0, sizeof(shellcode), PAGE_EXECUTE_READWRITE);
        FixShellcode(base, startAddr, parameter);
        SIZE_T bytesWritten = 0;
        access->WriteMemory(base, std::vector<BYTE>(&shellcode[0], &shellcode[sizeof(shellcode)]), bytesWritten);
        realEntryPoint = base;
    }

    InstrumentCallbackExecuter(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* startAddr = NULL;
    void* parameter = NULL;
    void* realEntryPoint = NULL;

#ifdef _WIN64
    inline static BYTE shellcode[] = { 0x90 };

    void FixShellcode(void* base)
    {
        ;
    }
#else
    //    0:  60                      pusha
    //    1 : 9c                      pushf
    //    2 : b8 01 00 00 00          mov    eax, 0x1
    //    7 : f0 0f c0 05 aa aa aa    lock xadd BYTE PTR ds : 0xaaaaaaaa, al
    //    e : aa
    //    f : 83 f8 00                cmp    eax, 0x0
    //    12 : 75 13                   jne    27 < exit >
    //    14 : 83 ec 40                sub    esp, 0x40
    //    17 : b8 bb bb bb bb          mov    eax, 0xbbbbbbbb
    //    1c : 50                      push   eax
    //    1d : b8 cc cc cc cc          mov    eax, 0xcccccccc
    //    22 : ff d0                   call   eax
    //    24 : 83 c4 40                add    esp, 0x40
    //    00000027 < exit > :
    //    27 : 9d                      popf
    //    28 : 61                      popa
    //    29 : ff e1                   jmp    ecx
    //    2b : 00                      db '0'
    inline static BYTE shellcode[] = { 0x60, 0x9C, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC0, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0x83, 0xF8, 0x00, 0x75, 0x13, 0x83, 0xEC, 0x40, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0x50, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD0, 0x83, 0xC4, 0x40, 0x9D, 0x61, 0xFF, 0xE1, 0x00 };
    void FixShellcode(void* base, void* target, void* param)
    {
        *(DWORD*)(&shellcode[11]) = (DWORD)base + 0x2b;
        *(DWORD*)(&shellcode[0x18]) = (DWORD)param;
        *(DWORD*)(&shellcode[0x1e]) = (DWORD)target;
    }
#endif
};






HANDLE GetProcessHandleByDuplication(int pid, DWORD access)
{
    return NULL;
}

void RegularInjectionMgr::DoInjection(int pid, const std::filesystem::path& dllPath, const std::vector<std::string>& methods)
{
    if (!CheckParameters(methods))
    {
        Common::ThrowException("Check parameters failed.");
    }
    std::string process_access_method = methods[0];
    std::string entry_point_method = methods[1];
    std::string gain_execution_method = methods[2];

    // 1. Get process access method
    std::unique_ptr<IProcessAccess> access;
    if (process_access_method == "OpenProcess")
    {
        auto target_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (target_handle == NULL)
        {
            Common::ThrowException("OpenProcess failed with %d", GetLastError());
        }
        Common::Print("[+] Process opened.");
        access.reset(new HandleProcessAccess(target_handle));
    }
    else if (process_access_method == "Duplicate Handle")
    {
        auto target_handle = GetProcessHandleByDuplication(pid, PROCESS_ALL_ACCESS);
        if (target_handle == NULL)
        {
            Common::ThrowException("Failed to get a handle.");
        }
        Common::Print("[+] Target handle get.");
        access.reset(new HandleProcessAccess(target_handle));
    }

    // 2. prepare entry point and parameters
    std::unique_ptr<IEntryPoint> entry;
    if (entry_point_method == "LoadLibrary")
    {
        LoadLibraryEntryPoint* loadlibrary_entry = new LoadLibraryEntryPoint(access.get());
        loadlibrary_entry->Prepare(dllPath.wstring());
        Common::Print("[+] Entrypoint LoadLibrary() successfully prepared.");
        entry.reset(loadlibrary_entry);     
    }
    else if (entry_point_method == "LdrLoadDll")
    {
        ;
    }
    else if (entry_point_method == "Manual Load")
    {
        ;
    }

    // 3. execute our entry point in target's context
    std::unique_ptr<IExecuter> executer;
    if (gain_execution_method == "CreateRemoteThread")
    {
        auto remotethread = new CreateRemoteThreadExecuter(access.get());
        remotethread->Prepare(entry->GetEntryPoint(), entry->GetParameter());
        Common::Print("[+] CreateRemoteThread executer set.");
        executer.reset(remotethread);
    }
    else if (gain_execution_method == "QueueUserAPC")
    {
        ;
    }
    else if (gain_execution_method == "InstrumentCallback")
    {
        auto ic = new InstrumentCallbackExecuter(access.get());
        ic->Prepare(entry->GetEntryPoint(), entry->GetParameter());
        Common::Print("[+] InstrumentCallback executer set.");
        executer.reset(ic);
    }

    // 4. go for it
    executer->Go();
}

bool RegularInjectionMgr::CheckParameters(const std::vector<std::string>& methods)
{
    return true;
}
