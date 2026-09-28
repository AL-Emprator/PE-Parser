#pragma once
#pragma once
#include <Windows.h>

/* PE_HDRS owns pFileBuffer and pSections. Release with FreePeHeaders. */
typedef struct _PE_HDRS {
    PBYTE pFileBuffer;
    DWORD dwFileSize;
    IMAGE_DOS_HEADER ImgDosHdr;
    DWORD dwNtSignature;
    IMAGE_FILE_HEADER ImgFileHdr;
    WORD wOptionalMagic;
    union {
        IMAGE_OPTIONAL_HEADER32 pe32;
        IMAGE_OPTIONAL_HEADER64 pe64;
    } ImgOptHdr;
    PIMAGE_SECTION_HEADER pSections;
    DWORD dwSectionCount;
    IMAGE_DATA_DIRECTORY DataDirectories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    BOOL bIsDllFile;
} PE_HDRS, * PPE_HDRS;

BOOL ReadFileFromDisk(LPCSTR fileName, PBYTE* buffer, PDWORD fileSize);
BOOL ParsePeFile(PBYTE buffer, DWORD fileSize, PPE_HDRS pe);
BOOL RvaToFileOffset(const PE_HDRS* pe, DWORD rva, DWORD bytesNeeded, PDWORD offset);
void FreePeHeaders(PPE_HDRS pe);
