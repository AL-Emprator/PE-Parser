#include "pe.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Windows.h>

static BOOL Fits(DWORD size, uint64_t offset, uint64_t length) {
    return offset <= size && length <= (uint64_t)size - offset;
}

BOOL ParsePeFile(PBYTE buffer, DWORD fileSize, PPE_HDRS pe) {
    uint64_t nt, opt, sectionTable, sectionBytes;
    WORD magic;
    DWORD directoryCount;
    const size_t directoryOffset32 = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
    const size_t directoryOffset64 = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    size_t directoryOffset, minimumOpt;

    if (!buffer || !pe) return FALSE;
    memset(pe, 0, sizeof(*pe));
    if (!Fits(fileSize, 0, sizeof(pe->ImgDosHdr))) return FALSE;
    memcpy(&pe->ImgDosHdr, buffer, sizeof(pe->ImgDosHdr));
    if (pe->ImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE || pe->ImgDosHdr.e_lfanew < 0)
        return FALSE;

    /* e_lfanew is a raw file offset, not an RVA. */
    nt = (uint64_t)pe->ImgDosHdr.e_lfanew;
    if (!Fits(fileSize, nt, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) return FALSE;
    memcpy(&pe->dwNtSignature, buffer + (size_t)nt, sizeof(DWORD));
    if (pe->dwNtSignature != IMAGE_NT_SIGNATURE) return FALSE;
    memcpy(&pe->ImgFileHdr, buffer + (size_t)nt + sizeof(DWORD),
        sizeof(pe->ImgFileHdr));
    opt = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!Fits(fileSize, opt, pe->ImgFileHdr.SizeOfOptionalHeader) ||
        pe->ImgFileHdr.SizeOfOptionalHeader < sizeof(WORD)) return FALSE;
    memcpy(&magic, buffer + (size_t)opt, sizeof(magic));
    pe->wOptionalMagic = magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        directoryOffset = directoryOffset32;
        minimumOpt = directoryOffset32;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        directoryOffset = directoryOffset64;
        minimumOpt = directoryOffset64;
    }
    else return FALSE;
    if (pe->ImgFileHdr.SizeOfOptionalHeader < minimumOpt) return FALSE;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        memcpy(&pe->ImgOptHdr.pe32, buffer + (size_t)opt,
            pe->ImgFileHdr.SizeOfOptionalHeader < sizeof(pe->ImgOptHdr.pe32)
            ? pe->ImgFileHdr.SizeOfOptionalHeader : sizeof(pe->ImgOptHdr.pe32));
        directoryCount = pe->ImgOptHdr.pe32.NumberOfRvaAndSizes;
    }
    else {
        memcpy(&pe->ImgOptHdr.pe64, buffer + (size_t)opt,
            pe->ImgFileHdr.SizeOfOptionalHeader < sizeof(pe->ImgOptHdr.pe64)
            ? pe->ImgFileHdr.SizeOfOptionalHeader : sizeof(pe->ImgOptHdr.pe64));
        directoryCount = pe->ImgOptHdr.pe64.NumberOfRvaAndSizes;
    }
    if (directoryCount > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        directoryCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if ((uint64_t)directoryCount * sizeof(IMAGE_DATA_DIRECTORY) >
        pe->ImgFileHdr.SizeOfOptionalHeader - directoryOffset) return FALSE;
    memcpy(pe->DataDirectories, buffer + (size_t)opt + directoryOffset,
        (size_t)directoryCount * sizeof(IMAGE_DATA_DIRECTORY));

    sectionTable = opt + pe->ImgFileHdr.SizeOfOptionalHeader;
    sectionBytes = (uint64_t)pe->ImgFileHdr.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!Fits(fileSize, sectionTable, sectionBytes)) return FALSE;
    if (sectionBytes) {
        pe->pSections = (PIMAGE_SECTION_HEADER)malloc((size_t)sectionBytes);
        if (!pe->pSections) return FALSE;
        memcpy(pe->pSections, buffer + (size_t)sectionTable, (size_t)sectionBytes);
    }
    pe->dwSectionCount = pe->ImgFileHdr.NumberOfSections;
    pe->bIsDllFile = (pe->ImgFileHdr.Characteristics & IMAGE_FILE_DLL) != 0;
    pe->pFileBuffer = buffer; /* ownership transfers only on success */
    pe->dwFileSize = fileSize;
    return TRUE;
}

BOOL RvaToFileOffset(const PE_HDRS* pe, DWORD rva, DWORD bytesNeeded, PDWORD offset) {
    DWORD i;
    uint64_t delta, raw;
    DWORD sizeOfHeaders;
    if (!pe || !offset || !pe->pFileBuffer || bytesNeeded == 0) return FALSE;
    sizeOfHeaders = pe->wOptionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
        ? pe->ImgOptHdr.pe32.SizeOfHeaders : pe->ImgOptHdr.pe64.SizeOfHeaders;
    if (rva < sizeOfHeaders && Fits(pe->dwFileSize, rva, bytesNeeded) &&
        (uint64_t)rva + bytesNeeded <= sizeOfHeaders) {
        *offset = rva;
        return TRUE;
    }
    for (i = 0; i < pe->dwSectionCount; ++i) {
        const IMAGE_SECTION_HEADER* s = &pe->pSections[i];
        if (rva < s->VirtualAddress) continue;
        delta = (uint64_t)rva - s->VirtualAddress;
        if (delta > s->SizeOfRawData || bytesNeeded > s->SizeOfRawData - delta)
            continue;
        raw = (uint64_t)s->PointerToRawData + delta;
        if (!Fits(pe->dwFileSize, raw, bytesNeeded)) continue;
        *offset = (DWORD)raw;
        return TRUE;
    }
    return FALSE;
}

void FreePeHeaders(PPE_HDRS pe) {
    if (!pe) return;
    free(pe->pSections);
    free(pe->pFileBuffer);
    memset(pe, 0, sizeof(*pe));
}
