# IAT Validator

A user-mode anti-cheat detection technique that identifies IAT (Import 
Address Table) hooks by validating each imported function's address 
against its expected location.

This README documents the full process — from learning the PE format, 
to manually analyzing a binary with a hex editor, to implementing 
working detection code in C++.

# 1- Understand PE File Structure

```
Offset 0x00   ┌──────────────────────────────────────────────────────┐
              │  IMAGE_DOS_HEADER  (64 bytes)                        │
              │  - e_magic: "MZ"                                     │
              │  - e_lfanew  ←  Offset to PE Header                  │
              ├──────────────────────────────────────────────────────┤
Offset ~0x40  │  DOS Stub Program                                    │
              │  "This program cannot be run in DOS mode."           │
              ├──────────────────────────────────────────────────────┤
   e_lfanew   │  PE Header                                           │
              │  ├─ Signature: "PE\0\0"                              │
              │  ├─ COFF File Header (20 bytes)                      │
              │  └─ Optional Header (224 or 240 bytes)               │
              │       │                                              │
              │       └─ Data Directories  (16 entries × 8 bytes)    │
              │             • Export Table                           │
              │             • Import Table                           │
              │             • Resource Table                         │
              │             • Exception Table                        │
              │             • Base Relocation Table (.reloc)         │
              │             • Debug Directory                        │
              │             • Import Address Table (IAT)   ← Index 12│
              │             • ... (other directories)                │
              ├──────────────────────────────────────────────────────┤
              │  Section Headers  (one entry per section)            │
              │  - .text     (code)                                  │
              │  - .rdata    (read-only data, imports, IAT)          │
              │  - .data     (initialized data)                      │
              │  - .rsrc     (resources)                             │
              │  - .reloc    (base relocations)                      │
              │  - .idata    (sometimes present)                     │
              │  ...                                                 │
              ├──────────────────────────────────────────────────────┤
              │  Image Sections  (the actual content)                │
              │  ├─ .text     → Machine code                         │
              │  ├─ .rdata    → Import Table + IAT + constants       │
              │  ├─ .data     → Global variables                     │
              │  ├─ .rsrc     → Icons, dialogs, version info         │
              │  ├─ .reloc    → Relocation information               │
              │  └─ ...                                              │
              └──────────────────────────────────────────────────────┘
```

Source: 
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [https://www.sunshine2k.de/reversing/tuts/tut_pe.htm](https://www.sunshine2k.de/reversing/tuts/tut_pe.htm)

# 2- Finding Import Address Table in PE executable file

<br>
- I think the first step is to become comfortable with the Windows executable binary format (PE). Let's identify some important parts.
- I will be using EasyAntiCheat binary as example for this studdy. File Hash = 652761ed1fa44955ffde4c3daeb0654937f7cdef7a3a05ddf509c2e707f46e0d

[Download Here](https://mega.nz/file/iopSTQRb#DbW3NH5TwKyamcgexjOqHiG-fLFd0mqZ7DaABeMwt5w)

<br>

<img width="1323" height="640" alt="Screenshot_1" src="https://github.com/user-attachments/assets/fa6c8285-7b21-499f-ac85-1649670a8ab4" />

# 3 - RVA vs File Offset

- IAT Address shown in the image above (0xa2000) is RVA address. To find the correct address of IAT in the file we will need to perform this calculation:

Offset = RVA (0xa2000) - Section VA (0xa2000) + PointerToRawData (0xa0800) = 0xa0800

- Wee can see these values opening the same binary on DetectItEasy (DIE) binary analysis tool:

<img width="654" height="158" alt="Screenshot_4" src="https://github.com/user-attachments/assets/860ba445-e67d-49b8-b8aa-7271617f519e" />

<br>

<img width="808" height="541" alt="Screenshot_2" src="https://github.com/user-attachments/assets/8cc89dd6-a478-4236-b7af-67fcfff219cb" />

<br>

The structure we found is called IMAGE_IMPORT_BY_NAME. The first 2 bytes are Hint (We'll use this information later when we develop the code. We'll ignore the hint).
Then we can see the ASCII text (Function Name)

# 4- Manually finding IMAGE_IMPORT_DESCRIPTOR's and Name

- Each IMAGE_IMPORT_DESCRIPTOR contains an imported DLL, its name, and the imported functions. We'll find it manually to better understand it before we start coding.

- From one of our sources: "After the PE Signature there is an RVA to the Import Directory. The Import Directory is an array of so-called IMAGE_IMPORT_DESCRIPTORs. From here, we can locate the imported DLL names along with their respective functions, as well as the Import Address Table (IAT) and the Import Lookup Table (ILT)."

<br>

- Import Table (RVA) -> found at 0xbe05c - For simplicity, find the address using the DiE tool:

<img width="892" height="468" alt="Screenshot_6" src="https://github.com/user-attachments/assets/1abcca6f-b4d1-485e-bd65-c1e0cef9a5ed" />

<br>

- Again, this is RVA (Relative Virtual Address), we need to calculate the VA.

- (RVA) Calculation: 0xbe05c - 0xa2000 + 0xa0800 = 0xBC85C

- 0xBC85C = Import Directory (So-called IMAGE_IMPORT_DESCRIPTORs)

<img width="828" height="319" alt="Screenshot_7" src="https://github.com/user-attachments/assets/1807cc78-6e17-4f0c-9c36-bac7aa90e422" />

<br>
<br>

- IMAGE_IMPORT_DESCRIPTOR looks like:
<img width="530" height="130" alt="Screenshot_8" src="https://github.com/user-attachments/assets/7b614cef-a3fc-4c48-b1a7-d7ef6fef2a26" />

- Remember: This is the structure that contains the DLL and function names.

- DWORD = 4 Bytes: If we jump 12 bytes, we find 'name': 

<img width="828" height="319" alt="Screenshot_9" src="https://github.com/user-attachments/assets/66605b33-23c6-4796-9338-bca2e03576e8" />

<br>

- found -> 0xbe4c6 (should be name )
  
- (RVA) Calculation: 0xbe4c6 - 0xa2000 + 0xa0800 = 0xBCCC6

- 0xBCCC6 -> If our calculations are correct, we should find a DLL name at this address

<img width="693" height="184" alt="Screenshot_10" src="https://github.com/user-attachments/assets/c1a8bc84-8de4-4417-9d14-2df43d9dfc35" />

<br>

# 5- File on HD X Memory

Before we move on, let's remember one important detail:

- If the file is on disk, IaT (IMAGE_IMPORT_DESCRIPTOR->FirstThunk) points to the function names. But if it's loaded on memory, it points to the libraries addresses (names are substituted by addresses - linker)

If loaded in memory: To obtain the names, we need to look at the ILT (Import Lookup Table: IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk)

# 6- How IAT Works

- After understanding the basics of PE structure and IAT, let's research how IAT Detection works:

For IaT detection in anti-cheat, since we are at runtime, we need to:

1- Follow the IaT to find the addresses of the libraries.

2- Find their names and use them to search for the original addresses. Compare the original addresses with the address in the IaT.

3- If different (outside the range of the original library), detect the Iat hook.

Since Windows overwrites the Iat with the addresses, you lose the names there. To obtain them, we need to look at the ILT (Import Lookup Table).

Warning: This technique has a minor issue with false positives! We'll address that later.

# 7- Windows API - (Study before implementation)

- So far we know the structure of a PE, what VA and RVA are, and the structure of IAT and ITL. Before moving on to the practical part, let's study some essential functions of the Windows API (well documented on the Microsoft website):

## GetModuleHandle

- What is a Module? On Windows a module is a executable program or DLL loaded into memory (e.g. exe, dll)
- What does it return?  A pointer to the module base
- What happens when you pass NULL as a parameter?  The handle to the calling program is returned
- Which header do you need to include? #include <windows.h>

[WinAPI-Documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)

---

## GetModuleInformation

- What is MODULEINFO and what fields does it have?  A windows API function that "Retrieves information about the specified module". [FIELDS](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo): lpBaseOfDll, SizeOfImage, EntryPoint
- Why does it need a process handle as a parameter?  (hProcess) To determine which program the function should obtain information from.
- Which header do you need to include? The include we will need when we start coding: #include <psapi.h>

[WinAPI-Documentation](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation)


---

## IMAGE_IMPORT_DESCRIPTOR

- How many fields does this struct have? 5 fields: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
- Which field points to the DLL name?  Name. (e.g. user32.dll) -> this field does not change
- Which field points to IAT?  FirstThunk ( This is where Windows "writes" the actual address of the function into memory after the program loads. )
- Which field points to ILT?  OriginalFirstThunk
- How do you know you've reached the end of the descriptor array? When see 0x14 bytes long zeros, it is the end of our array of IMAGE_IMPORT_DESCRIPTORs.

[Reference](https://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)

---

## IMAGE_THUNK_DATA

- What does each entry in this struct represent?  
- What is the difference between its value before and after Windows loads the executable? Before loading (on disk), the field points to the name of the function, e.g. MessageBoxA (via an RVA). After the Windows loader runs, this pointer is overwritten by the actual memory address (VA) of the function inside the DLL (e.g. user32.dll).

---

# 8- CODING

- Finally, the practical part. After learning every little bit of the process, the code is easy to understand.

## Get Import Table Address
```
HMODULE hModule = GetModuleHandleA(NULL); // Module handle
    if (hModule == NULL) { 
        cout << "Failed to find process handle" << endl; 
        return 0; 
    }

    MODULEINFO mInfo = {};

    HANDLE currProcess = GetCurrentProcess(); // Get current process handle

    GetModuleInformation(currProcess, hModule, &mInfo, sizeof(MODULEINFO)); // Get process info, and store it on MODULEINFO struct

    uintptr_t base = reinterpret_cast<uintptr_t>(mInfo.lpBaseOfDll); // Cast from VOID* to perform calculations
    cout << "Base: 0x" << hex << base << endl;

    PIMAGE_NT_HEADERS ntHeaders;
    ntHeaders = ImageNtHeader(mInfo.lpBaseOfDll); // Get ntHeaders struct
    /*
      typedef struct _IMAGE_NT_HEADERS {
        DWORD                   Signature;
        IMAGE_FILE_HEADER       FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
      } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
    */

    IMAGE_OPTIONAL_HEADER optHeader = ntHeaders->OptionalHeader; // OptionalHeader (contains data directory address)

    IMAGE_DATA_DIRECTORY imgDataDirectory = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; 
    cout << "imgDataDirectory: 0x" << hex << imgDataDirectory.VirtualAddress << endl;

    uintptr_t importTableVA = imgDataDirectory.VirtualAddress;
    uintptr_t importTable = imgDataDirectory.VirtualAddress + base;
    cout << "importTable: 0x" << hex << importTable << endl << endl;
```

  ## Comparison Logic
```
- Loop through IMPORT_DESCRIPTORs
- For each IMPORT_DESCRIPTOR:
  - Get DLL Name and address
  - For each IMAGE_THUNK_DATA:
   - Get function Address
   - If ourside DLL address, print: IAT Hook Detected!
```

<img width="380" height="202" alt="cc301808 pe2fig06(en-us,msdn 10)" src="https://github.com/user-attachments/assets/93985941-8c64-4b8d-8d11-02c1d83504e1" />


IMPORT_DESCRIPTOR struct format is defined above in this file.
IMAGE_THUNK_DATA is the array of pointers to the functions imported from the DLL.

Loop PseudoCode:

```
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
```

Code implementation:

```
DWORD nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // DLL NAME
    while(nameRVA != 0){ // loop IMPORT_DESCRIPTORs
        uintptr_t nameAddr = base + nameRVA;
        cout << "Checking DLL: " << reinterpret_cast<char*>(nameAddr) << endl;
        HMODULE firstThunkModule = GetModuleHandleA(reinterpret_cast<char*>(nameAddr));
        MODULEINFO currModuleInfo = {};
        GetModuleInformation(currProcess, firstThunkModule, &currModuleInfo, sizeof(MODULEINFO)); // GET DLL MEMORY RANGE
        
        DWORD firstThunkRVA = *reinterpret_cast<DWORD*>(importTable + 0x10); //  IMAGE_THUNK_DATAs
        uintptr_t firstThunkAddr = base + firstThunkRVA;
        uintptr_t address = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
        while( address != 0 ){ // End indicated by an IMAGE_THUNK_DATA element with a value of zero
            uintptr_t size = reinterpret_cast<uintptr_t>(currModuleInfo.lpBaseOfDll) + currModuleInfo.SizeOfImage;
            if( address > size || address < reinterpret_cast<uintptr_t>(currModuleInfo.lpBaseOfDll) ) { cout << "Warning: IAT Hook Detected!" << endl; }
            firstThunkAddr += sizeof(uintptr_t);
            address = *reinterpret_cast<uintptr_t*>(firstThunkAddr);
        }

        importTable += 0x14; // Move to the next struct 
        nameRVA = *reinterpret_cast<DWORD*>(importTable + 0x0C); // NEXT DLL NAME
    }
   
    system("pause");
```

Compile:  g++ iat.cpp -o iat.exe -static-libgcc -static-libstdc++ -ldbghelp <br>
Execute: ./iat.exe

# 9- Limitations

<img width="477" height="538" alt="image" src="https://github.com/user-attachments/assets/5168cffa-a5c9-4d72-baac-84587bbad6d1" />
<br>

As you can see we get false positives with "KERNEL32.dll". This occurs because of a Windows mechanism known as API Forwarding. Many Windows system APIs are not implemented within the DLL where they are exported. Instead, the DLL contains a "forwarder" entry that redirects the call to another module (typically kernelbase.dll or ntdll.dll). 

## 10- Technical Solution

To resolve this, the anti-cheat must compare IAT entries against addresses resolved via GetProcAddress rather than checking if they fall within the specific module's memory bounds.

I've updated the code to address this issue, and now it works as expected:

<img width="1088" height="252" alt="image" src="https://github.com/user-attachments/assets/bb6f4f73-5cfa-4999-9e31-118984d24894" />
<br>
<img width="722" height="568" alt="image" src="https://github.com/user-attachments/assets/cd70c9c6-17fe-4d25-ba72-8e81ed630097" />
<br>
<img width="712" height="224" alt="image" src="https://github.com/user-attachments/assets/c5dfb56a-0d82-4c0e-83cb-f30d52b0d67a" />
<br>
<img width="656" height="623" alt="image" src="https://github.com/user-attachments/assets/ffba22a4-5605-4688-a54b-6a9f908792e6" />

## 11- IAT Hook Simulation

The implementation features an iatHook() function designed to simulate a classic IAT injection attack. It leverages VirtualProtect to gain write access to the module's Import Address Table, overwrites the target function pointer (e.g., Sleep), and restores the original memory protection flags. This routine serves as a controlled test case to validate the effectiveness of the anti-cheat's detection engine.
