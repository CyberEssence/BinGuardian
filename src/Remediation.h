#pragma once
#include <windows.h>
#include <string>

class Remediation {
public:
    static bool UnloadDll(DWORD pid, const std::wstring& dllPath, HMODULE hModule);
    static bool TerminateProcess(DWORD pid);
    static bool DeleteDllFile(const std::wstring& filePath);
    static bool RestoreSystemDll(const std::wstring& targetPath, const std::wstring& backupPath);
};