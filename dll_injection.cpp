#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

// Функция для проверки, является ли модуль стандартной системной DLL
bool IsSystemDll(HMODULE hModule)
{
    TCHAR moduleName[MAX_PATH];
    if (GetModuleFileNameEx(GetCurrentProcess(), hModule, moduleName, MAX_PATH))
    {
        TCHAR systemPath[MAX_PATH];
        GetSystemDirectory(systemPath, MAX_PATH);

        TCHAR* moduleNameWithoutPath = _tcsrchr(moduleName, '\\');
        if (moduleNameWithoutPath != nullptr)
        {
            TCHAR fullSystemDllPath[MAX_PATH];
            _stprintf_s(fullSystemDllPath, MAX_PATH, _T("%s\\%s"), systemPath, moduleNameWithoutPath + 1);

            if (_tcsicmp(moduleName, fullSystemDllPath) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

int main()
{
    // Получение списка всех процессов
    DWORD processIds[1024];
    DWORD numProcesses;
    if (EnumProcesses(processIds, sizeof(processIds), &numProcesses))
    {
        // Получение количества процессов
        DWORD numTotalProcesses = numProcesses / sizeof(DWORD);

        // Поиск в каждом процессе
        for (DWORD i = 0; i < numTotalProcesses; i++)
        {
            // Открытие процесса
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
            if (hProcess != nullptr)
            {
                TCHAR processName[MAX_PATH];

                // Получение имени процесса
                if (GetModuleBaseName(hProcess, nullptr, processName, sizeof(processName) / sizeof(TCHAR)))
                {
                    // Выводим имя процесса и его ID
                    std::wcout << L"Process Name: " << processName << L", ID: " << processIds[i] << std::endl;

                    // Получение списка модулей процесса
                    HMODULE hModules[1024];
                    DWORD numModules;
                    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &numModules))
                    {
                        DWORD numTotalModules = numModules / sizeof(HMODULE);

                        // Поиск модулей, не являющихся системными DLL
                        for (DWORD j = 0; j < numTotalModules; j++)
                        {
                            if (!IsSystemDll(hModules[j]))
                            {
                                TCHAR moduleName[MAX_PATH];
                                if (GetModuleFileNameEx(hProcess, hModules[j], moduleName, MAX_PATH))
                                {
                                    // Выводим путь к модулю
                                    std::wcout << L"Injected DLL: " << moduleName << std::endl;
                                }
                            }
                        }
                    }
                }
            }

            // Закрытие процесса
            CloseHandle(hProcess);
        }
    }

    return 0;
}
