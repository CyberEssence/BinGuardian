#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <string>
#pragma comment(lib, "advapi32.lib")

bool GetFileSha1(const char* filename, BYTE* hash, DWORD* hashLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile); return false;
    }
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); CloseHandle(hFile); return false;
    }

    BYTE buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }

    DWORD len = *hashLen;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); CloseHandle(hFile); return false;
    }
    *hashLen = len;

    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); CloseHandle(hFile);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc == 3) {
        // Режим командной строки: compare.exe <base_file> <current_file>
        const char* baseFile = argv[1];
        const char* currentFile = argv[2];

        BYTE hashBase[20], hashCurrent[20];
        DWORD lenBase = 20, lenCurrent = 20;

        if (!GetFileSha1(baseFile, hashBase, &lenBase)) {
            printf("Base file not found, copying current to base...\n");
            if (CopyFileA(currentFile, baseFile, FALSE)) printf("Base file created.\n");
            else printf("Copy failed.\n");
            return 0;
        }

        if (!GetFileSha1(currentFile, hashCurrent, &lenCurrent)) {
            printf("Current file not found.\n"); return 1;
        }

        if (lenBase == lenCurrent && memcmp(hashBase, hashCurrent, lenBase) == 0)
            printf("Files are identical.\n");
        else
            printf("Files are different.\n");
    }
    else {
        // Интерактивный режим (старый)
        char baseFile[256], currentFile[256];
        printf("Enter base file name: ");
        scanf_s("%255s", baseFile, (unsigned)sizeof(baseFile));
        printf("Enter current file name: ");
        scanf_s("%255s", currentFile, (unsigned)sizeof(currentFile));

        BYTE hashBase[20], hashCurrent[20];
        DWORD lenBase = 20, lenCurrent = 20;

        if (!GetFileSha1(baseFile, hashBase, &lenBase)) {
            printf("Base file not found, copying current to base...\n");
            if (CopyFileA(currentFile, baseFile, FALSE)) printf("Base file created.\n");
            else printf("Copy failed.\n");
            return 0;
        }

        if (!GetFileSha1(currentFile, hashCurrent, &lenCurrent)) {
            printf("Current file not found.\n"); return 1;
        }

        if (lenBase == lenCurrent && memcmp(hashBase, hashCurrent, lenBase) == 0)
            printf("Files are identical.\n");
        else
            printf("Files are different.\n");
    }

    return 0;
}