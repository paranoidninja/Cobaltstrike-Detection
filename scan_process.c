#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Compile with:
// x86_64-w64-mingw32-gcc scan_memory.c -o scan_memory.exe -m64 -s -O2

// replace this with your pattern
BYTE pattern[] = { 0x49, 0xB9, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x49, 0x0F, 0xAF, 0xD1, 0x49, 0x83, 0xF8, 0x40 };
// BYTE pattern[] = { 0x49, 0x8D, 0x55, 0x02, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x44, 0x0F, 0xB7, 0xF8, 0xB8, 0xFF, 0x03, 0x00, 0x00 }; // second pattern

BOOL verbosity = FALSE;

void printDebug(DWORD processId, HANDLE hProcess, PVOID scanAddress, BOOL failedHandle) {
    if (verbosity) {
        if (processId) {
            printf("[*] Scanning process: %lu\n", processId);
        }
        if (hProcess) {
            printf("[*] Handle acquired: 0x%x\n", hProcess);
        }
        if (scanAddress) {
            printf("[*] Scanning address: %p\n", scanAddress);
        }
        if (failedHandle) {
            printf("[-] Failed to acquire handle: %lu\n", processId);
        }
    }
}

void scanProcessMemory(HANDLE processHandle, BYTE* pattern, DWORD patternSize, DWORD processId) {
    MEMORY_BASIC_INFORMATION memoryInfo;
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    BYTE* buffer = NULL;
    SIZE_T bytesRead;
    for (LPVOID address = systemInfo.lpMinimumApplicationAddress; address < systemInfo.lpMaximumApplicationAddress; address = (LPVOID)((DWORD_PTR)address + memoryInfo.RegionSize)) {
        if (VirtualQueryEx(processHandle, address, &memoryInfo, sizeof(memoryInfo))) {
            if ((memoryInfo.State == MEM_COMMIT) && (memoryInfo.Protect == PAGE_EXECUTE_READWRITE || memoryInfo.Protect == PAGE_EXECUTE_READ)) {
                printDebug(0, 0, address, 0);
                buffer = (BYTE*)malloc(memoryInfo.RegionSize);
                if (ReadProcessMemory(processHandle, address, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (DWORD i = 0; i < bytesRead - patternSize + 1; ++i) {
                        if (memcmp(buffer + i, pattern, patternSize) == 0) {
                            printf("[+] Process: %lu\n", processId);
                            printf("[+] Cobaltstrike beacon found: 0x%p\n", memoryInfo.BaseAddress);
                            printf("[+] Pattern match at: 0x%p\n", address + i);
                            return;
                        }
                    }
                }
                free(buffer);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    printf("[*] Scanning all processes. Might take a while. Use '-v' for verbosity\n");
    printf("[*] Make sure to run this program with high integrity so that privileged processes can also be scanned\n");
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        verbosity = TRUE;
    }
    PROCESSENTRY32 ProcessEntry32;
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (! hSnapShot) {
        return 0;
    }
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
    if (! Process32First( hSnapShot, &ProcessEntry32)) {
        return 0;
    }
    do {
        DWORD patternSize = sizeof(pattern) / sizeof(pattern[0]);
        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry32.th32ProcessID);
        if (processHandle) {
            printDebug(ProcessEntry32.th32ProcessID, processHandle, 0, 0);
            scanProcessMemory(processHandle, pattern, patternSize, ProcessEntry32.th32ProcessID);
            CloseHandle(processHandle);
        } else {
            printDebug(ProcessEntry32.th32ProcessID, 0, 0, TRUE);
        }
        if (verbosity) {
            printf("\n");
        }
    } while(Process32Next(hSnapShot, &ProcessEntry32));
    return 0;
}
