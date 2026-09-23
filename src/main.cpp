#include <iostream>
#include <vector>
#include <locale>
#include <string>
#include <io.h>
#include <fcntl.h>
#include "Scanner.h"
#include "Remediation.h"

// Вывод справки
void PrintHelp() {
    std::wcout << L"BinGuardian - утилита для поиска и лечения DLL-инъекций\n\n";
    std::wcout << L"Использование:\n";
    std::wcout << L"  BinGuardian.exe [команда] [параметры]\n\n";
    std::wcout << L"Команды:\n";
    std::wcout << L"  --scan, -s              Сканировать все процессы\n";
    std::wcout << L"  --kill, -k <PID>        Завершить процесс по ID\n";
    std::wcout << L"  --delete, -d <путь>     Удалить файл DLL\n";
    std::wcout << L"  --restore, -r <цель> <бэкап>  Восстановить DLL из копии\n";
    std::wcout << L"  --help, -h              Показать справку\n\n";
    std::wcout << L"Без параметров — интерактивный режим.\n";
}

// Интерактивный режим
void RunInteractive() {
    Scanner scanner;
    auto suspicious = scanner.ScanAllProcesses();

    if (suspicious.empty()) {
        std::wcout << L"Подозрительных DLL не найдено.\n";
        return;
    }

    std::wcout << L"Найдено подозрительных DLL: " << suspicious.size() << L"\n\n";

    for (auto& item : suspicious) {
        std::wcout << L"Процесс: " << item.processName << L" (PID=" << item.processId << L")\n";
        std::wcout << L"  DLL: " << item.modulePath << L"\n";
        std::wcout << L"  Системная: " << (item.isSystemDll ? L"Да" : L"Нет")
            << L", Подписана MS: " << (item.isSignedByMicrosoft ? L"Да" : L"Нет") << L"\n";

        wchar_t choice;
        std::wcout << L"  [U] Выгрузить, [K] Завершить, [D] Удалить, [R] Восстановить, [S] Пропустить: ";
        std::wcin >> choice;

        switch (choice) {
        case L'U': case L'u': Remediation::UnloadDll(item.processId, item.modulePath, item.moduleHandle); break;
        case L'K': case L'k': Remediation::TerminateProcess(item.processId); break;
        case L'D': case L'd':
            if (!item.isSystemDll) Remediation::DeleteDllFile(item.modulePath);
            else std::wcout << L"Нельзя удалять системный файл.\n";
            break;
        case L'R': case L'r':
            if (item.isSystemDll) {
                std::wcout << L"Путь к эталонной копии DLL: ";
                std::wstring backup;
                std::wcin >> backup;
                Remediation::RestoreSystemDll(item.modulePath, backup);
            }
            else {
                std::wcout << L"Восстановление только для системных DLL.\n";
            }
            break;
        default: std::wcout << L"Пропущено.\n"; break;
        }
        std::wcout << L"\n";
    }
}

int wmain(int argc, wchar_t* argv[]) {
    // Правильная настройка локали и потоков для русского текста
    setlocale(LC_ALL, "Russian");
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    if (argc == 1) {
        RunInteractive();
        return 0;
    }

    std::wstring command = argv[1];

    if (command == L"--help" || command == L"-h") {
        PrintHelp();
    }
    else if (command == L"--scan" || command == L"-s") {
        std::wcout << L"Сканирование процессов...\n";
        Scanner scanner;
        auto suspicious = scanner.ScanAllProcesses();
        std::wcout << L"Найдено подозрительных DLL: " << suspicious.size() << L"\n\n";
        for (const auto& item : suspicious) {
            std::wcout << L"PID: " << item.processId
                << L" | " << item.processName
                << L" | Системная: " << (item.isSystemDll ? L"Да" : L"Нет")
                << L" | MS: " << (item.isSignedByMicrosoft ? L"Да" : L"Нет") << L"\n"
                << L"     " << item.modulePath << L"\n";
        }
    }
    else if (command == L"--kill" || command == L"-k") {
        if (argc < 3) { std::wcerr << L"Укажите PID. Пример: BinGuardian.exe -k 1234\n"; return 1; }
        DWORD pid = std::stoul(argv[2]);
        if (Remediation::TerminateProcess(pid)) std::wcout << L"Процесс " << pid << L" завершен.\n";
        else std::wcerr << L"Не удалось завершить процесс.\n";
    }
    else if (command == L"--delete" || command == L"-d") {
        if (argc < 3) { std::wcerr << L"Укажите путь. Пример: BinGuardian.exe -d C:\\bad.dll\n"; return 1; }
        if (Remediation::DeleteDllFile(argv[2])) std::wcout << L"Файл удален.\n";
        else std::wcerr << L"Не удалось удалить файл.\n";
    }
    else if (command == L"--restore" || command == L"-r") {
        if (argc < 4) { std::wcerr << L"Пример: BinGuardian.exe -r C:\\target.dll C:\\backup.dll\n"; return 1; }
        if (Remediation::RestoreSystemDll(argv[2], argv[3])) std::wcout << L"Восстановлено.\n";
        else std::wcerr << L"Не удалось восстановить.\n";
    }
    else {
        std::wcerr << L"Неизвестная команда: " << command << L"\n";
        PrintHelp();
        return 1;
    }

    return 0;
}