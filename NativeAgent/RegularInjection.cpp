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
            Common::Print("[+] DebugPrivilege enabled.");
        }
        else
        {
            Common::Print("[!] Set privilege failed(Did you run this program as administrator?)");
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
        else  // TODO: test on win7 and win8
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
        throw std::exception("Not implemented");
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
        std::exception("Not Implemented");
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
        std::exception("Not Implemented");
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

class QueueUserAPCExecuter : public IExecuter
{
public:
    virtual void Go() override
    {
        ;
    }

    void Prepare(void* startAddr, void* parameter)
    {
        this->startAddr = startAddr;
        this->parameter = parameter;
    }

    QueueUserAPCExecuter(IProcessAccess* access)
    {
        this->access = access;
        throw std::exception("Not implemented");
    }

private:
    IProcessAccess* access = NULL;
    void* startAddr = NULL;
    void* parameter = NULL;
};

// See https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html
// Shellcode generated by https://defuse.ca/online-x86-assembler.htm#disassembly
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
        Common::Print("[+] Instrumentcallback written to 0x%p", base);
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
 /*     0:  9c                      pushf
        1 : 80 3d 6c 00 00 00 00    cmp    BYTE PTR[rip + 0x6c], 0x0        # 74 < realExit + 0x5 >
        8:  75 65                   jne    6f <realExit>
        a : 50                      push   rax
        b : 53                      push   rbx
        c : 51                      push   rcx
        d : 52                      push   rdx
        e : 41 50                   push   r8
        10 : 41 51                   push   r9
        12 : 41 52                   push   r10
        14 : 41 53                   push   r11
        16 : 41 54                   push   r12
        18 : 41 55                   push   r13
        1a : 41 56                   push   r14
        1c : 41 57                   push   r15
        1e : 55                      push   rbp
        1f : 57                      push   rdi
        20 : 56                      push   rsi
        21 : 48 c7 c0 01 00 00 00    mov    rax, 0x1
        28 : f0 0f c0 05 43 00 00    lock xadd BYTE PTR[rip + 0x43], al        # 73 < realExit + 0x4 >
        2f: 00
        30 : 3c 00                   cmp    al, 0x0
        32 : 75 24                   jne    58 < exit >
        34 : 48 b9 aa aa aa aa aa    movabs rcx, 0xaaaaaaaaaaaaaaaa
        3b : aa aa aa
        3e : 48 b8 bb bb bb bb bb    movabs rax, 0xbbbbbbbbbbbbbbbb
        45 : bb bb bb
        48 : 48 89 e5                mov    rbp, rsp
        4b : 48 83 ec 20             sub    rsp, 0x20
        4f : 48 83 e4 f0 and rsp, 0xfffffffffffffff0
        53 : ff d0                   call   rax
        55 : 48 89 ec                mov    rsp, rbp
        0000000000000058 <exit> :
        58 : 5e                      pop    rsi
        59 : 5f                      pop    rdi
        5a : 5d                      pop    rbp
        5b : 41 5f                   pop    r15
        5d : 41 5e                   pop    r14
        5f : 41 5d                   pop    r13
        61 : 41 5c                   pop    r12
        63 : 41 5b                   pop    r11
        65 : 41 5a                   pop    r10
        67 : 41 59                   pop    r9
        69 : 41 58                   pop    r8
        6b : 5a                      pop    rdx
        6c : 59                      pop    rcx
        6d : 5b                      pop    rbx
        6e : 58                      pop    rax
        000000000000006f <realExit> :
        6f : 9d                      popf
        70 : 41 ff e2                jmp    r10*/
    inline static BYTE shellcode[] = { 0x9C, 0x80, 0x3D, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x75, 0x65, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x55, 0x57, 0x56, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC0, 0x05, 0x43, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x75, 0x24, 0x48, 0xB9, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xE4, 0xF0, 0xFF, 0xD0, 0x48, 0x89, 0xEC, 0x5E, 0x5F, 0x5D, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D, 0x41, 0xFF, 0xE2, 0x00 };

    void FixShellcode(void* base, void* target, void* param)
    {
        *(__int64*)(&shellcode[0x36]) = (__int64)param;
        *(__int64*)(&shellcode[0x40]) = (__int64)target;
    }
#else  
    //    0:  9c                      pushf
    //    1 : 80 3d aa aa aa aa 00    cmp    BYTE PTR ds : 0xaaaaaaaa, 0x0
    //    8 : 75 26                   jne    30 < realExit >
    //    a : 60                      pusha
    //    b : b8 01 00 00 00          mov    eax, 0x1
    //    10 : f0 0f c0 05 aa aa aa    lock xadd BYTE PTR ds : 0xaaaaaaaa, al
    //    17 : aa
    //    18 : 83 f8 00                cmp    eax, 0x0
    //    1b : 75 12                   jne    2f < exit>
    //    1d : 83 ec 40                sub    esp, 0x40
    //    20 : 68 aa aa aa aa          push   0xaaaaaaaa
    //    25 : b8 bb bb bb bb          mov    eax, 0xbbbbbbbb
    //    2a : ff d0                   call   eax
    //    2c : 83 c4 40                add    esp, 0x40
    //    0000002f <exit> :
    //    2f : 61                      popa
    //    00000030 < realExit > :
    //    30 : 9d                      popf
    //    31 : ff e1                   jmp    ecx
    inline static BYTE shellcode[] = { 0x9C, 0x80, 0x3D, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x75, 0x26, 0x60, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC0, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0x83, 0xF8, 0x00, 0x75, 0x12, 0x83, 0xEC, 0x40, 0x68, 0xAA, 0xAA, 0xAA, 0xAA, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xFF, 0xD0, 0x83, 0xC4, 0x40, 0x61, 0x9D, 0xFF, 0xE1, 0x00 };
    
    void FixShellcode(void* base, void* target, void* param)
    {
        *(DWORD*)(&shellcode[3]) = (DWORD)base + 0x33;
        *(DWORD*)(&shellcode[0x14]) = (DWORD)base + 0x33;
        *(DWORD*)(&shellcode[0x21]) = (DWORD)param;
        *(DWORD*)(&shellcode[0x26]) = (DWORD)target;
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
        access.reset(new HandleProcessAccess(target_handle));
        Common::Print("[+] Process opened.");
    }
    else if (process_access_method == "Duplicate Handle")
    {
        auto target_handle = GetProcessHandleByDuplication(pid, PROCESS_ALL_ACCESS);
        if (target_handle == NULL)
        {
            Common::ThrowException("Failed to get a handle.");
        }
        access.reset(new HandleProcessAccess(target_handle));
        Common::Print("[+] Target handle get.");      
    }
    else if (process_access_method == "Kernel")
    {
        auto kernelAccess = new KernelProcessAccess();
        access.reset(kernelAccess);
        Common::Print("[+] Kernel access prepared.");
    }

    // 2. prepare entry point and parameters
    std::unique_ptr<IEntryPoint> entry;
    if (entry_point_method == "LoadLibrary")
    {
        LoadLibraryEntryPoint* loadlibrary_entry = new LoadLibraryEntryPoint(access.get());
        loadlibrary_entry->Prepare(dllPath.wstring());
        entry.reset(loadlibrary_entry);   
        Common::Print("[+] Entrypoint LoadLibrary() successfully prepared."); 
    }
    else if (entry_point_method == "LdrLoadDll")
    {
        auto ldrLoadDll_entry = new LdrLoadDllEntryPoint(access.get());
        ldrLoadDll_entry->Prepare();
        entry.reset(ldrLoadDll_entry);
        Common::Print("[+] Entrypoint LdrLoadDll() successfully prepared.");
    }
    else if (entry_point_method == "Manual Load")
    {
        auto manualLoad = new ManualLoadEntryPoint();
        manualLoad->Prepare();
        entry.reset(manualLoad);
        Common::Print("[+] Entrypoint manual load successfully prepared.");
    }

    // 3. execute our entry point in target's context
    std::unique_ptr<IExecuter> executer;
    if (gain_execution_method == "CreateRemoteThread")
    {
        auto remotethread = new CreateRemoteThreadExecuter(access.get());
        remotethread->Prepare(entry->GetEntryPoint(), entry->GetParameter());    
        executer.reset(remotethread);
        Common::Print("[+] CreateRemoteThread executer set.");
    }
    else if (gain_execution_method == "QueueUserAPC")
    {
        auto apc = new QueueUserAPCExecuter();
        apc->Prepare(entry->GetEntryPoint(), entry->GetParameter());
        executer.reset(apc);
        Common::Print("[+] QueueUserAPC executor set.");
    }
    else if (gain_execution_method == "InstrumentCallback")
    {
        auto ic = new InstrumentCallbackExecuter(access.get());
        ic->Prepare(entry->GetEntryPoint(), entry->GetParameter()); 
        executer.reset(ic);
        Common::Print("[+] InstrumentCallback executer set.");
    }

    // 4. go for it
    executer->Go();
}

bool RegularInjectionMgr::CheckParameters(const std::vector<std::string>& methods)
{
    return true;
}
