#include "pe.h"
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>

BOOL ReadFileFromDisk(LPCSTR fileName, PBYTE* buffer, PDWORD fileSize) {
    HANDLE file;
    LARGE_INTEGER size;
    PBYTE data;
    DWORD got;

    if (!fileName || !buffer || !fileSize) return FALSE;
    *buffer = NULL;
    *fileSize = 0;
    file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > UINT32_MAX) {
        CloseHandle(file);
        return FALSE;
    }
    data = (PBYTE)malloc((size_t)size.QuadPart);
    if (!data) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, data, (DWORD)size.QuadPart, &got, NULL) ||
        got != (DWORD)size.QuadPart) {
        free(data);
        CloseHandle(file);
        return FALSE;
    }
    CloseHandle(file);
    *buffer = data;
    *fileSize = got;
    return TRUE;
}
