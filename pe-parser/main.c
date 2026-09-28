#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main(int argc, char** argv) {
    PBYTE buffer = NULL;
    DWORD size = 0, i, importOffset;
    PE_HDRS pe = { 0 };
    const IMAGE_DATA_DIRECTORY* imports;

    if (argc != 2) {
        fprintf(stderr, "Usage: pe-parser.exe <path-to-exe-or-dll>\n");
        return 1;
    }
    if (!ReadFileFromDisk(argv[1], &buffer, &size)) {
        fprintf(stderr, "Could not read file.\n");
        return 1;
    }
    if (!ParsePeFile(buffer, size, &pe)) {
        fprintf(stderr, "Invalid or unsupported PE file.\n");
        free(buffer); /* ParsePeFile takes ownership only when successful */
        return 1;
    }
    printf("Format: PE%s\n", pe.wOptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "32+" : "32");
    printf("Machine: 0x%04X  DLL: %s  Sections: %lu\n",
        (unsigned)pe.ImgFileHdr.Machine, pe.bIsDllFile ? "yes" : "no",
        (unsigned long)pe.dwSectionCount);
    for (i = 0; i < pe.dwSectionCount; ++i) {
        const IMAGE_SECTION_HEADER* s = &pe.pSections[i];
        printf("%-8.8s RVA: 0x%08lX  raw offset: 0x%08lX  raw size: 0x%08lX\n",
            (const char*)s->Name, (unsigned long)s->VirtualAddress,
            (unsigned long)s->PointerToRawData, (unsigned long)s->SizeOfRawData);
    }
    imports = &pe.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports->VirtualAddress != 0 &&
        RvaToFileOffset(&pe, imports->VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR), &importOffset))
        printf("Import table RVA: 0x%08lX, file offset: 0x%08lX\n",
            (unsigned long)imports->VirtualAddress, (unsigned long)importOffset);
    FreePeHeaders(&pe);
    return 0;
}
