#pragma once
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>

struct SuspiciousModule {
    DWORD processId;
    std::wstring processName;
    HMODULE moduleHandle;
    std::wstring modulePath;
    bool isSystemDll;
    bool isSignedByMicrosoft;
};

class Scanner {
public:
    std::vector<SuspiciousModule> ScanAllProcesses();
private:
    std::wstring GetProcessName(DWORD pid);
};