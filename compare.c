#include <windows.h>
#include <stdio.h>

bool CheckFileExists(const char* filename) {
    DWORD attr = GetFileAttributes(filename);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool CreateBaseFile() {
    char baseFilePath[256];
    char currentFilePath[256];

    printf("Enter name of base file: ");
    scanf("%249s", baseFilePath);

    printf("Enter name of current file: ");
    scanf("%249s", currentFilePath);

    const char* baseFilePathConst = baseFilePath;
    const char* currentFilePathConst = currentFilePath;

    if (CheckFileExists(baseFilePathConst)) {
        return true;
    }

    HANDLE hSrc = CreateFileA(currentFilePathConst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        return false;
    }

    HANDLE hDst = CreateFileA(baseFilePathConst, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc);
        return false;
    }

    DWORD bytesRead;
    ReadFile(hSrc, NULL, 0, &bytesRead, NULL);
    WriteFile(hDst, NULL, bytesRead, &bytesRead, NULL);

    CloseHandle(hSrc);
    CloseHandle(hDst);

    return true;
}

int main() {
    if (!CreateBaseFile()) {
        printf("Base binary file does not exist\n");
    } else {
        printf("Files are same\n");
    }

    return 0;
}
