#include <windows.h>
#include <psapi.h>
#include <iostream>
# include <dbghelp.h>

using namespace std;

// Work in progress / learning PE navigation and IAT validation

int main() {

    cout << "Starting Anti-Cheat - IAT Hook Detector" << endl;

    HMODULE hModule = GetModuleHandleA(NULL);
    if (hModule == NULL) { 
        cout << "Failed to find process handle" << endl; 
        return 0; 
    }

    MODULEINFO mInfo = {};

    GetModuleInformation(GetCurrentProcess(), hModule, &mInfo, sizeof(MODULEINFO));

    uintptr_t base = reinterpret_cast<uintptr_t>(mInfo.lpBaseOfDll);
    cout << "Base: 0x" << hex << base << endl;

    PIMAGE_NT_HEADERS ntHeaders;
    ntHeaders = ImageNtHeader(mInfo.lpBaseOfDll); // (https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagentheader)

    IMAGE_OPTIONAL_HEADER optHeader = ntHeaders->OptionalHeader; // (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)

    IMAGE_DATA_DIRECTORY imgDataDirectory = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)
    cout << "imgDataDirectory: 0x" << hex << imgDataDirectory.VirtualAddress << endl;

    // 104/120	Import table address and size    /      192/208	Import address table address and size
    uintptr_t importTableVA = imgDataDirectory.VirtualAddress;
    uintptr_t importTable = imgDataDirectory.VirtualAddress + base;
    cout << "importTable: 0x" << hex << importTable << endl;

    DWORD nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C);
    uintptr_t nameAddr = base + nameRVA;

    cout << "firstName: " << reinterpret_cast<char*>(nameAddr) << endl;

    /*
        ImportDirectory: Loop this array. For each structure:
        - Get function name. Read function address from IAT
        - Read DLL name, get DLL address
        - If function address outside DLL address: IAT Hook detected!
    */

    string val;
    cout << "Press any key do exit" << endl;
    cin >> val;

    return 0;
}
