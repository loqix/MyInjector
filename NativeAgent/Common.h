#pragma once
#include <windows.h>
#include <algorithm>
#include <string>
#include <iostream>

namespace Common
{
    inline void Print(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        int len = _vscprintf(fmt, args) + 1;
        char* formatted = (char*)malloc(len * sizeof(char));
        vsprintf_s(formatted, len, fmt, args);
        va_end(args);      
        std::cout << formatted << std::endl;
        free(formatted);
    }

    inline void ThrowException(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        int len = _vscprintf(fmt, args) + 1;
        static char* buffer = (char*)malloc(1024 * 1024);
        vsprintf_s(buffer, len, fmt, args);
        va_end(args);
        throw std::exception(buffer);
    }

    inline std::wstring StringToWString(const std::string& str, UINT codePage = CP_ACP) 
    {
        int num = MultiByteToWideChar(codePage, 0, str.c_str(), -1, NULL, 0);
        wchar_t* wide = new wchar_t[num];
        MultiByteToWideChar(codePage, 0, str.c_str(), -1, wide, num);
        std::wstring w_str(wide);
        delete[] wide;
        return w_str;
    }

    inline std::string WStringToString(const std::wstring& wstr, UINT codePage = CP_ACP)
    {
        int num = WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, NULL, 0, 0, 0);
        char* converted = (char*)malloc(num + 1);
        WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, converted, num + 1, 0, 0);
        std::string ret = converted;
        free(converted);
        return ret;
    }

}