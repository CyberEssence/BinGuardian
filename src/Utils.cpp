#include "Utils.h"
#include <softpub.h>
#include <iostream>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

bool Utils::IsSystemPath(const std::wstring& path) {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring systemPath(sysDir);

    wchar_t sysWow64Dir[MAX_PATH];
    GetSystemWow64DirectoryW(sysWow64Dir, MAX_PATH);
    std::wstring sysWow64Path(sysWow64Dir);

    auto startsWith = [](const std::wstring& str, const std::wstring& prefix) {
        return str.size() >= prefix.size() &&
            _wcsnicmp(str.c_str(), prefix.c_str(), prefix.size()) == 0;
        };

    return startsWith(path, systemPath) || startsWith(path, sysWow64Path);
}

bool Utils::IsMicrosoftSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wintrustData = { 0 };
    wintrustData.cbStruct = sizeof(WINTRUST_DATA);
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &wintrustData);

    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wintrustData);

    return status == ERROR_SUCCESS;
}

std::wstring Utils::GetFileNameFromPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return path.substr(pos + 1);
    }
    return path;
}