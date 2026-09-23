#include "Scanner.h"
#include "Utils.h"
#include <iostream>

std::wstring Scanner::GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return L"Unknown";

    wchar_t processName[MAX_PATH] = L"<unknown>";
    if (GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH)) {
        CloseHandle(hProcess);
        return std::wstring(processName);
    }
    CloseHandle(hProcess);
    return L"Unknown";
}

std::vector<SuspiciousModule> Scanner::ScanAllProcesses() {
    std::vector<SuspiciousModule> result;
    DWORD processIds[1024], bytesReturned;

    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned))
        return result;

    DWORD count = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < count; ++i) {
        if (processIds[i] == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
        if (!hProcess) continue;

        HMODULE modules[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
            DWORD modCount = cbNeeded / sizeof(HMODULE);
            for (DWORD j = 0; j < modCount; ++j) {
                wchar_t modulePath[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, modules[j], modulePath, MAX_PATH)) {
                    std::wstring path(modulePath);
                    bool isSys = Utils::IsSystemPath(path);
                    bool isSigned = Utils::IsMicrosoftSigned(path);

                    if (!isSys || !isSigned) {
                        SuspiciousModule sm;
                        sm.processId = processIds[i];
                        sm.processName = GetProcessName(processIds[i]);
                        sm.moduleHandle = modules[j];
                        sm.modulePath = path;
                        sm.isSystemDll = isSys;
                        sm.isSignedByMicrosoft = isSigned;
                        result.push_back(sm);
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
    return result;
}