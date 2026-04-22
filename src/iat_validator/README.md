# First Steps
Studdy to understand better how IAT works and how to implement Anti-Cheat IAT Detection.

# 1- Understand PE File Structure

```
Offset 0x00   ┌──────────────────────────────────────────────────────┐
              │  IMAGE_DOS_HEADER  (64 bytes)                        │
              │  - e_magic: "MZ"                                     │
              │  - e_lfanew  ←  Offset to PE Header                 │
              ├──────────────────────────────────────────────────────┤
Offset ~0x40  │  DOS Stub Program                                    │
              │  "This program cannot be run in DOS mode."           │
              ├──────────────────────────────────────────────────────┤
   e_lfanew   │  PE Header                                           │
              │  ├─ Signature: "PE\0\0"                             │
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
              │  ├─ .text     → Machine code                          │
              │  ├─ .rdata    → Import Table + IAT + constants        │
              │  ├─ .data     → Global variables                      │
              │  ├─ .rsrc     → Icons, dialogs, version info          │
              │  ├─ .reloc    → Relocation information                │
              │  └─ ...                                              │
              └──────────────────────────────────────────────────────┘
```

Source: 
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [https://www.sunshine2k.de/reversing/tuts/tut_pe.htm](https://www.sunshine2k.de/reversing/tuts/tut_pe.htm)

# 2- Finding Import Address Table in PE executable file

<br>

- I will be using EasyAntiCheat binary as example for this studdy. File Hash = 652761ed1fa44955ffde4c3daeb0654937f7cdef7a3a05ddf509c2e707f46e0d

<br>

<img width="1323" height="640" alt="Screenshot_1" src="https://github.com/user-attachments/assets/fa6c8285-7b21-499f-ac85-1649670a8ab4" />

# 3 - RVA vs File Offset

IAT Address (0xa2000) is RVA address. To find the IAT in the file:

Offset = RVA (0xa2000) - Section VA (0xa2000) + PointerToRawData (0xa0800) = 0xa0800

Wee can see these values opening the same binary on DetectItEasy (DIE):

<img width="654" height="158" alt="Screenshot_4" src="https://github.com/user-attachments/assets/860ba445-e67d-49b8-b8aa-7271617f519e" />

<br>

<img width="808" height="541" alt="Screenshot_2" src="https://github.com/user-attachments/assets/8cc89dd6-a478-4236-b7af-67fcfff219cb" />

The structure we found seems to be called IMAGE_IMPORT_BY_NAME. The first 2 bytes are Hint (ignore them).
Then we can see the ASCII text (Function Name)

# 3- File on HD X Memory

If the file is on HD, IaT points tothe function names. But if it's loaded on memory, it points to the libraries addresses (names are substituted by addresses - linker)

If loaded in memory: To obtain the names, we need to look at the ILT (Import Lookup Table).

# 4- How IAT Works

For IaT detection in anti-cheat, since we are at runtime, we need to:

1- Follow the IaT to find the addresses of the libraries.

2- Find their names and use them to search for the original addresses. Compare the original addresses with the address in the IaT.

3- If different (outside the range of the original library), detect the Iat hook.

Since Windows overwrites the Iat with the addresses, you lose the names there. To obtain them, we need to look at the ILT (Import Lookup Table).

# 5- Windows API - (Study before implementation)

## 1. GetModuleHandle

- What is a Module? On Windows a module is a executable program or DLL loaded into memory (e.g. exe, dll)
- What does it return?  A pointer to the module base
- What happens when you pass NULL as a parameter?  The handle to the calling program is returned
- Which header do you need to include? #include <windows.h>

[WinAPI-Documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)

---

## 2. GetModuleInformation

- What is MODULEINFO and what fields does it have?  A windows API function that "Retrieves information about the specified module". [FIELDS](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo): lpBaseOfDll, SizeOfImage, EntryPoint
- Why does it need a process handle as a parameter?  (hProcess) To determine which program the function should obtain information from.
- Which header do you need to include? The include we will need when we start coding: #include <psapi.h>

[WinAPI-Documentation](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo)


---

## 3. IMAGE_IMPORT_DESCRIPTOR

- How many fields does this struct have? 5 fields: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
- Which field points to the DLL name?  Name. (e.g. user32.dll) -> this field does not change
- Which field points to IAT?  FirstThunk ( This is where Windows "writes" the actual address of the function into memory after the program loads. )
- Which field points to ILT?  OriginalFirstThunk
- How do you know you've reached the end of the descriptor array? When see 0x14 bytes long zeros, it is the end of our array of IMAGE_IMPORT_DESCRIPTORs.

[Reference](https://www.sunshine2k.de/reversing/tuts/tut_rvait.htm)

---

## 4. IMAGE_THUNK_DATA

- What does each entry in this struct represent?  
- What is the difference between its value before and after Windows loads the executable? Before loading (on disk), the field points to the name of the function, e.g. MessageBoxA (via an RVA). After the Windows loader runs, this pointer is overwritten by the actual memory address (VA) of the function inside the DLL (e.g. user32.dll).

---

# 6- Manually finding IMAGE_IMPORT_DESCRIPTOR's and Name

<br>

- Import Table (RVA) -> found at 0xbe05c - Using DiE:

<img width="892" height="468" alt="Screenshot_6" src="https://github.com/user-attachments/assets/1abcca6f-b4d1-485e-bd65-c1e0cef9a5ed" />

<br>

- (RVA) Calculation: 0xbe05c - 0xa2000 + 0xa0800 = 0xBC85C

- 0xBC85C = Import Directory (So-called IMAGE_IMPORT_DESCRIPTORs)

<img width="828" height="319" alt="Screenshot_7" src="https://github.com/user-attachments/assets/1807cc78-6e17-4f0c-9c36-bac7aa90e422" />

<br>
<br>

<img width="530" height="130" alt="Screenshot_8" src="https://github.com/user-attachments/assets/7b614cef-a3fc-4c48-b1a7-d7ef6fef2a26" />

- DWORD = 4 Bytes

- If we jump, after 12 bytes we find name: 

<img width="828" height="319" alt="Screenshot_9" src="https://github.com/user-attachments/assets/66605b33-23c6-4796-9338-bca2e03576e8" />

<br>

- found -> 0xbe4c6 (should be name )
  
- (RVA) Calculation: 0xbe4c6 - 0xa2000 + 0xa0800 = 0xBCCC6

- 0xBCCC6 -> If our calculations are correct, we should find a DLL name at this address

<img width="693" height="184" alt="Screenshot_10" src="https://github.com/user-attachments/assets/c1a8bc84-8de4-4417-9d14-2df43d9dfc35" />




