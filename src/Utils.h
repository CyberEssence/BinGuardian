#pragma once
#include <windows.h>
#include <string>

class Utils {
public:
    static bool IsSystemPath(const std::wstring& path);
    static bool IsMicrosoftSigned(const std::wstring& filePath);
    static std::wstring GetFileNameFromPath(const std::wstring& path);
};