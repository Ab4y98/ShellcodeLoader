// Ab4y98 : github.com/Ab4y98

#include <windows.h>
#include <iostream>
#include <string>


VOID printFunction(INT);

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


int writeShellcodeToFile(unsigned char* shellcode, DWORD shellcodeSize) {
    // File path to save the shellcode
        const char* filePath = "shellcode_enc.bin";

    // Create or open the file
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not create file. Error code: %lu\n", GetLastError());
        return 1;
    }

    // Write the shellcode to the file
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, shellcode, shellcodeSize, &bytesWritten, NULL)) {
        printf("Error: Could not write to file. Error code: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    // Close the file handle
    CloseHandle(hFile);
    return 0;
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


int main(int argc, char* argv[]) {
    // Ensure the user provides the required arguments
    if (argc != 3) {
        printf("Usage: %s <file_path> <key>\n", argv[0]);
        return 1;
    }

    // Extract file path and key from arguments
    const char* filePath = argv[1];
    const char* key = argv[2];
    size_t keySize = strlen(key);

    // Convert file path to wide string
    wchar_t wFilePath[MAX_PATH];
    size_t convertedChars = 0;
    errno_t err = mbstowcs_s(&convertedChars, wFilePath, MAX_PATH, filePath, _TRUNCATE);
    if (err != 0) {
        // Handle the error if necessary
        printf("Error converting multibyte to wide string.\n");
        return 1;
    }

    // Load shellcode from file
    DWORD shellcodeSize = 0;
    unsigned char* shellcode = LoadShellcode(wFilePath, &shellcodeSize);
    if (!shellcode) {
        fprintf(stderr, "Failed to load shellcode from file: %s\n", filePath);
        return 1;
    }

    // XOR the shellcode with the provided key
    XorByInputKey(PBYTE(shellcode), shellcodeSize, PBYTE(key), keySize);

    // Write the modified shellcode back to a file
    writeShellcodeToFile(shellcode, shellcodeSize);

    // Clean up
    free(shellcode);

    printf("\n");
    printFunction(1);

    int length = strlen(key);  // Get the length of the input string

    printf("unsigned char key[] = {", length);

    for (int i = 0; i < length; i++) {
        printf("0x%02X", (unsigned char)key[i]);  // Print each char in hexadecimal
        if (i < length - 1) {
            printf(", ");  // Print comma between elements except after the last one
        }
    }
    printf("};\n");

    printFunction(2);

    return 0;
}
