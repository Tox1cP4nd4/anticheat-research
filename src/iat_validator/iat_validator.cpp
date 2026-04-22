#include <windows.h>
#include <psapi.h>
#include <iostream>

using namespace std;

// Work in progress / learning PE navigation and IAT validation
// in the future: Instead of calculating offsets manually, use Windows SDK ready-made structs.

/*
Goal
-------------

1 - Get Module Base
GetModuleInformation() -> get lpBaseOfDll (module base address) X

PE header pointer = base address + 0x3C

PE header pointer + 0x80 = ImportDirectory

ImportDirectory: Loop this array. For each structure:
- Get function name. Read function address from IAT
- Read DLL name, get DLL address
- If function address outside DLL address: IAT Hook detected!

*/

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

    uintptr_t peHeaderAddr = *reinterpret_cast<uintptr_t*>(base + 0x3C);

    uintptr_t ImportDirectoryRVA = peHeaderAddr + 0x80;

    uintptr_t ImportDirectoryVA = base + ImportDirectoryRVA;

    cout << "Base: 0x" << hex << base << endl;
    cout << "PE Header: 0x" << hex << peHeaderAddr << endl;
    cout << "Import Directory RVA: 0x" << hex << ImportDirectoryRVA << endl;
    cout << "Import Directory VA: 0x" << hex << ImportDirectoryVA << endl;

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
