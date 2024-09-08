#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>        // For Windows API functions (e.g., OpenSCManager, StartService)
#include <stdio.h>          // For printf
#include <tchar.h>          // For Unicode and ASCII handling (optional but recommended)
#include <string>           // For std::string and std::wstring
#include <iostream>         // For input/output streams
#include <winternl.h>       // For NT functions and types (optional depending on what you use)
#include "driver_handler.h"
#define IOCTL_HELLO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

std::wstring char_to_wstring(const char* str) {
    size_t size = strlen(str) + 1;
    std::wstring wstr(size, L'\0');
    mbstowcs(&wstr[0], str, size);
    return wstr;
}


// Function to load the unsigned driver
void load_driver_lazy(const char* driver_name, const char* bin_path) {
    SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!sc_manager) {
        printf("[!] Failed to open Service Control Manager. Error: %ld\n", GetLastError());
        return;
    }

    std::wstring w_driver_name = char_to_wstring(driver_name);
    std::wstring w_bin_path = char_to_wstring(bin_path);

    // Check if the service already exists
    SC_HANDLE sc_service = OpenService(sc_manager, w_driver_name.c_str(), SERVICE_START | DELETE | SERVICE_QUERY_STATUS);
    if (sc_service) {
        printf("[*] Service already exists: %s\n", driver_name);

        // Query service status
        SERVICE_STATUS_PROCESS status;
        DWORD bytes_needed;
        if (QueryServiceStatusEx(sc_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)) {
            if (status.dwCurrentState == SERVICE_RUNNING) {
                printf("[*] Driver service is already running: %s\n", driver_name);
            }
            else if (status.dwCurrentState == SERVICE_STOPPED) {
                printf("[*] Driver service is stopped, attempting to start: %s\n", driver_name);
                if (!StartService(sc_service, 0, NULL)) {
                    printf("[!] Failed to start driver service. Error: %ld\n", GetLastError());
                }
                else {
                    printf("[*] Driver service started successfully: %s\n", driver_name);
                }
            }
            else {
                printf("[*] Driver service is in an unknown state. Attempting to restart...\n");
                ControlService(sc_service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status);  // Stop if needed
                if (!StartService(sc_service, 0, NULL)) {
                    printf("[!] Failed to restart driver service. Error: %ld\n", GetLastError());
                }
                else {
                    printf("[*] Driver service restarted successfully: %s\n", driver_name);
                }
            }
        }
    }
    else {
        printf("[*] Creating service for driver: %s\n", driver_name);
        sc_service = CreateService(
            sc_manager,
            w_driver_name.c_str(),
            w_driver_name.c_str(),
            SERVICE_START | DELETE | SERVICE_QUERY_STATUS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            w_bin_path.c_str(),
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (!sc_service) {
            printf("[!] Failed to create service. Error: %ld\n", GetLastError());
            CloseServiceHandle(sc_manager);
            return;
        }

        printf("[*] Successfully created service for driver: %s\n", driver_name);

        // Start the driver service
        if (!StartService(sc_service, 0, NULL)) {
            printf("[!] Failed to start driver service. Error: %ld\n", GetLastError());
        }
        else {
            printf("[*] Driver service started successfully: %s\n", driver_name);
        }
    }

    CloseServiceHandle(sc_service);
    CloseServiceHandle(sc_manager);
}

// Function to unload the driver
void unload_driver_lazy(const char* driver_name) {
    SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!sc_manager) {
        printf("[!] Failed to open Service Control Manager. Error: %ld\n", GetLastError());
        return;
    }

    std::wstring w_driver_name = char_to_wstring(driver_name);

    // Open the service
    SC_HANDLE sc_service = OpenService(sc_manager, w_driver_name.c_str(), SERVICE_STOP | DELETE);
    if (!sc_service) {
        printf("[!] Failed to open driver service for unloading. Error: %ld\n", GetLastError());
        CloseServiceHandle(sc_manager);
        return;
    }

    // Stop the driver service
    SERVICE_STATUS status;
    if (!ControlService(sc_service, SERVICE_CONTROL_STOP, &status)) {
        DWORD error_code = GetLastError();
        if (error_code == ERROR_SERVICE_NOT_ACTIVE) {
            printf("[*] Driver service is already stopped: %s\n", driver_name);
        }
        else {
            printf("[!] Failed to stop driver service. Error: %ld\n", error_code);
        }
    }
    else {
        printf("[*] Driver service stopped successfully: %s\n", driver_name);
    }

    // Delete the driver service
    if (!DeleteService(sc_service)) {
        printf("[!] Failed to delete driver service. Error: %ld\n", GetLastError());
    }
    else {
        printf("[*] Driver service deleted successfully: %s\n", driver_name);
    }

    CloseServiceHandle(sc_service);
    CloseServiceHandle(sc_manager);
}

bool send_ioctl_hello(HANDLE driver_handle) {
    DWORD bytes_returned;
    char input_buffer[] = "Hello from user-mode!";
    char output_buffer[256] = { 0 };

    BOOL success = DeviceIoControl(driver_handle,
        IOCTL_HELLO,  // Use the corrected IOCTL code
        input_buffer,
        sizeof(input_buffer),
        output_buffer,
        sizeof(output_buffer),
        &bytes_returned,
        NULL);

    if (success) {
        printf("[*] IOCTL Hello succeeded! Driver responded with: %s\n", output_buffer);
        return true;
    }
    else {
        DWORD error_code = GetLastError();
        printf("[!] IOCTL Hello failed. Error: %ld (0x%lx)\n", error_code, error_code);
        return false;
    }
}


HANDLE open_driver_handle(const char* driver_name) {
    // Replace the symbolic link path with the correct one
    std::string driver_path = "\\\\.\\EDR";  // Correct symbolic link as per the driver code

    HANDLE driver_handle = CreateFileA(driver_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (driver_handle == INVALID_HANDLE_VALUE) {
        DWORD error_code = GetLastError();
        printf("[!] Failed to open handle to driver: %s. Error: %ld (0x%lx)\n", driver_name, error_code, error_code);
        return nullptr;
    }

    printf("[*] Opened handle to driver: %s\n", driver_name);
    return driver_handle;
}



void close_driver_handle(HANDLE driver_handle) {
    if (driver_handle) {
        CloseHandle(driver_handle);
        printf("[*] Driver handle closed.\n");
    }
}
