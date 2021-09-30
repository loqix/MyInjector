#include <windows.h>
#include "RegularInjection.h"
#include <memory>
#include <iostream>
#include "Common.h"

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

class InstrumentCallbackExecuter : public IExecuter
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

    InstrumentCallbackExecuter(IProcessAccess* access)
    {
        this->access = access;
    }

private:
    IProcessAccess* access = NULL;
    void* startAddr = NULL;
    void* parameter = NULL;


    inline static BYTE shellcode[] = { 0x90 };
    inline static BYTE shellcode[] = { 0x90 };
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
