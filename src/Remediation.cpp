#include "Remediation.h"
#include <iostream>

bool Remediation::UnloadDll(DWORD pid, const std::wstring& dllPath, HMODULE hModule) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Не удалось открыть процесс " << pid << L"\n";
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");
    if (!pFreeLibrary) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, hModule, 0, NULL);
    if (!hThread) {
        std::wcerr << L"Не удалось создать удалённый поток\n";
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        std::wcout << L" DLL выгружена успешно.\n";
        return true;
    }
    else {
        std::wcerr << L" Ошибка выгрузки (код: " << exitCode << L")\n";
        return false;
    }
}

// ВОТ ЭТИ ТРИ ФУНКЦИИ У ВАС ПРОПУЩЕНЫ:
bool Remediation::TerminateProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Не удалось открыть процесс для завершения\n";
        return false;
    }
    bool result = ::TerminateProcess(hProcess, 0);
    CloseHandle(hProcess);
    return result;
}

bool Remediation::DeleteDllFile(const std::wstring& filePath) {
    if (DeleteFileW(filePath.c_str())) {
        std::wcout << L" Файл удалён успешно.\n";
        return true;
    }
    if (MoveFileExW(filePath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
        std::wcout << L" Файл будет удалён после перезагрузки.\n";
        return true;
    }
    std::wcerr << L" Не удалось удалить файл. Ошибка: " << GetLastError() << L"\n";
    return false;
}

bool Remediation::RestoreSystemDll(const std::wstring& targetPath, const std::wstring& backupPath) {
    if (CopyFileW(backupPath.c_str(), targetPath.c_str(), FALSE)) {
        std::wcout << L" Системная DLL восстановлена.\n";
        return true;
    }
    std::wcerr << L" Не удалось восстановить DLL. Ошибка: " << GetLastError() << L"\n";
    return false;
}