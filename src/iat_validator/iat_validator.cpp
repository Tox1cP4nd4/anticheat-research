#include <windows.h>
#include <psapi.h>
#include <iostream>
# include <dbghelp.h>

using namespace std;

// Work in progress / learning PE navigation and IAT validation

int main() {

    cout << endl << "+==========================================+" << endl;
    cout << " -> Starting Anti-Cheat - IAT Hook Detector" << endl;
    cout << "+==========================================+" << endl << endl;

    HMODULE hModule = GetModuleHandleA(NULL);
    if (hModule == NULL) { 
        cout << "Failed to find process handle" << endl; 
        return 0; 
    }

    MODULEINFO mInfo = {};

    HANDLE currProcess = GetCurrentProcess();

    GetModuleInformation(currProcess, hModule, &mInfo, sizeof(MODULEINFO));

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
    cout << "importTable: 0x" << hex << importTable << endl << endl;


    // (https://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)
    // LOOP THROUGH IMPORT_DESCRIPTORs:

    /*
    Loop through descriptors: 
        reads nameRVA at (importTable + 0x0C) 
        if nameRVA == 0: break 

        nameAddr = base + nameRVA 
        gets moduleInfo from the DLL with the name 
        calculates dllStart and dllEnd (dllStart + SizeOfImage) 

        firstThunkRVA = reads (importTable + 0x10) 
        thunkAddr = base + firstThunkRVA 

        Loop through the thunks: 
            address = reads *thunkAddr 
            if address == 0: break 

            if address < dllStart OR address > dllEnd: 
            HOOK DETECTED 

            thunkAddr += 8 (on x64) 

        importTable += 0x14 (next descriptor)
    */

    DWORD nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // DLL NAME
    while(nameRVA != 0){ // loop IMPORT_DESCRIPTORs
        uintptr_t nameAddr = base + nameRVA;
        cout << "Checking DLL: " << reinterpret_cast<char*>(nameAddr) << endl;
        HMODULE firstThunkModule = GetModuleHandleA(reinterpret_cast<char*>(nameAddr));
        MODULEINFO currModuleInfo = {};
        GetModuleInformation(currProcess, firstThunkModule, &currModuleInfo, sizeof(MODULEINFO)); // GET DLL MEMORY RANGE
        
        DWORD firstThunkRVA = *reinterpret_cast<DWORD*>(importTable + 0x10); //  IMAGE_THUNK_DATAs
        uintptr_t firstThunkAddr = base + firstThunkRVA; // Address ?
        uintptr_t address = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
        while( address != 0 ){ // lop IMAGE_THUNK_DATAs, " The ends of both arrays are indicated by an IMAGE_THUNK_DATA element with a value of zero"
            uintptr_t size = reinterpret_cast<uintptr_t>(currModuleInfo.lpBaseOfDll) + currModuleInfo.SizeOfImage;
            if( address > size || address < reinterpret_cast<uintptr_t>(currModuleInfo.lpBaseOfDll) ) { cout << "Warning: IAT Hook Detected!" << endl; }
            firstThunkAddr += 0x8; // 8 bytes to the next pointer ??
            address = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
        }

        importTable += 0x14; // Move to the next struct 
        nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // NEXT DLL NAME
    }
   
    system("pause");

    return 0;
}
