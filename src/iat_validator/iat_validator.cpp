#include <windows.h>
#include <psapi.h>
#include <iostream>
# include <dbghelp.h>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>

using namespace std;

void iatHook(IMAGE_DATA_DIRECTORY imgDataDirectory, uintptr_t base) {
  
    cout << endl << "[i] Starting IAT Hook on KERNEL32.dll, Sleep Function..." << endl;

    uintptr_t importTableVA = imgDataDirectory.VirtualAddress;
    uintptr_t importTable = imgDataDirectory.VirtualAddress + base;

    DWORD nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // DLL NAME
    string dllName = " ";
    while(dllName != "KERNEL32.dll"){ // loop IMPORT_DESCRIPTORs
        uintptr_t nameAddr = base + nameRVA;
        dllName = reinterpret_cast<char*>(nameAddr);

        if( dllName == "KERNEL32.dll" ) { cout << endl << "[i] DLL Found -> " << dllName << endl;  }

        HMODULE dllModuleHandle = GetModuleHandleA(reinterpret_cast<char*>(nameAddr));
        
        DWORD originalFirstThunkRVA = *reinterpret_cast<DWORD*>(importTable);
        uintptr_t originalFirstThunkAddr = base + originalFirstThunkRVA;

        DWORD firstThunkRVA = *reinterpret_cast<DWORD*>(importTable + 0x10);
        uintptr_t firstThunkAddr = base + firstThunkRVA;
        uintptr_t iatFuncAddress = *reinterpret_cast<uintptr_t*>(firstThunkAddr);

        DWORD functionRVA =  *reinterpret_cast<DWORD*>(originalFirstThunkAddr);
        uintptr_t funcNameAddress = base + functionRVA + 0x2;
        string functionName = " ";
        while( functionRVA != 0 && dllName == "KERNEL32.dll" ){

            functionName =  reinterpret_cast<char*>(funcNameAddress);

            if( functionName == "Sleep" ){ 
                cout << endl << "[i] Function has been Found! -> " << functionName << endl; 
                
                /*
                    BOOL VirtualProtect(
                        [in]  LPVOID lpAddress,
                        [in]  SIZE_T dwSize,
                        [in]  DWORD  flNewProtect,
                        [out] PDWORD lpflOldProtect
                    );
                */

                // IAT HOOK (CHANGE FUNC ADDRESS)
                // (https://learn.microsoft.com/pt-br/windows/win32/Memory/memory-protection-constants)

                DWORD oldProtect;
                cout << endl << "[i] Changing memory permissions to: PAGE_READWRITE" << endl;
                VirtualProtect((LPVOID)firstThunkAddr, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect);
                *(uintptr_t*)firstThunkAddr = (uintptr_t)0x476f6d6964657321;
                VirtualProtect((LPVOID)firstThunkAddr, sizeof(uintptr_t), oldProtect, &oldProtect);
                cout << endl << "[*] Changed (KERNEL32.dll) Sleep function address!" << endl << endl;
            }

            FARPROC realFuncAddress = GetProcAddress(dllModuleHandle, functionName.c_str()); // get real function address

            originalFirstThunkAddr += sizeof(uintptr_t); // next function name
            functionRVA =  *reinterpret_cast<DWORD*>(originalFirstThunkAddr);
            funcNameAddress = base + functionRVA + 0x2;

            firstThunkAddr += sizeof(uintptr_t); // next function address
            iatFuncAddress = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
        }

        importTable += 0x14; // Move to the next struct 
        nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // Next DLL Name
    }

}

int main() {

    cout << endl << "+==========================================+" << endl;
    cout << " -> Starting Anti-Cheat: IAT Hook Detector" << endl;
    cout << "+==========================================+" << endl << endl;

    string option = " "; 
    cout << "Perform IAT Hook simulation ? [y/n] ";
    cin >> option;

    bool performHook = (option == "y" || option == "Y") ? true : false;

    HMODULE hModule = GetModuleHandleA(NULL);
    if (hModule == NULL) { 
        cout << "Failed to find process handle" << endl; 
        return 0; 
    }

    MODULEINFO mInfo = {};

    HANDLE currProcess = GetCurrentProcess();

    GetModuleInformation(currProcess, hModule, &mInfo, sizeof(MODULEINFO));

    uintptr_t base = reinterpret_cast<uintptr_t>(mInfo.lpBaseOfDll);
    cout << endl << "-----------------------" << endl;
    cout << "Base: 0x" << hex << base << endl;

    PIMAGE_NT_HEADERS ntHeaders;
    ntHeaders = ImageNtHeader(mInfo.lpBaseOfDll); // (https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagentheader)

    IMAGE_OPTIONAL_HEADER optHeader = ntHeaders->OptionalHeader; // (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)

    IMAGE_DATA_DIRECTORY imgDataDirectory = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)
    cout << "imgDataDirectory: 0x" << hex << imgDataDirectory.VirtualAddress << endl;
    cout << "-----------------------" << endl << endl;
    
    if(performHook) iatHook(imgDataDirectory, base); // Simulate IAT Hook to test detection

    bool flagged = false;
    while(!flagged){
        uintptr_t importTableVA = imgDataDirectory.VirtualAddress;
        uintptr_t importTable = imgDataDirectory.VirtualAddress + base;

        DWORD nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // DLL NAME
        while(nameRVA != 0 && !flagged){ // loop IMPORT_DESCRIPTORs
            uintptr_t nameAddr = base + nameRVA;
            if(!performHook) cout << "Checking DLL: " << reinterpret_cast<char*>(nameAddr) << endl;

            HMODULE dllModuleHandle = GetModuleHandleA(reinterpret_cast<char*>(nameAddr));

            // originalFirstThunk stores Function Names
            DWORD originalFirstThunkRVA = *reinterpret_cast<DWORD*>(importTable); //  IMAGE_THUNK_DATAs
            uintptr_t originalFirstThunkAddr = base + originalFirstThunkRVA;

            // firstThunkAddr stores Function Address (in runtime)
            DWORD firstThunkRVA = *reinterpret_cast<DWORD*>(importTable + 0x10); //  IMAGE_THUNK_DATAs
            uintptr_t firstThunkAddr = base + firstThunkRVA;
            uintptr_t iatFuncAddress = *reinterpret_cast<uintptr_t*>(firstThunkAddr);

            DWORD functionRVA =  *reinterpret_cast<DWORD*>(originalFirstThunkAddr); // IMAGE_IMPORT_BY_NAMEs (https://stackoverflow.com/questions/41581363/how-we-can-get-hint-in-image-import-by-name-struct-in-pe-file) (https://www.cnblogs.com/walfud/articles/2608019.html)
            uintptr_t funcNameAddress = base + functionRVA + 0x2;
            string functionName = " ";
            while( functionRVA != 0 ){

                functionName =  reinterpret_cast<char*>(funcNameAddress);
                if(!performHook) cout << "Checking Function: " << functionName << endl;               

                FARPROC realFuncAddress = GetProcAddress(dllModuleHandle, functionName.c_str()); // get real function address

                if (functionName == "Sleep" && performHook) { cout << "[i] Sleep Function Address: 0x" << hex << iatFuncAddress << endl; cout << "[i] Original Sleep Function Address: 0x" << hex << (uintptr_t)realFuncAddress << endl << endl; }

                if( realFuncAddress != (FARPROC)iatFuncAddress ){ cout << endl << "[X] IAT Hook Detected!" << endl << endl; flagged = true; break;}

                originalFirstThunkAddr += sizeof(uintptr_t); // next function name
                functionRVA =  *reinterpret_cast<DWORD*>(originalFirstThunkAddr);
                funcNameAddress = base + functionRVA + 0x2;

                firstThunkAddr += sizeof(uintptr_t); // next function address
                iatFuncAddress = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
            }

            importTable += 0x14; // Move to the next struct 
            nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // Next DLL Name
        }
        if(!flagged){ 
            cout << endl << "[i] Nothing wrong here... IAT not detected." << endl << endl;
            cout << endl << "[i] Sleeping for 5000ms. Press CTR + C to stop." << endl << endl;
            this_thread::sleep_for(chrono::milliseconds(5000));
        } else {
            system("pause");
        }
    }

    return 0;
}
