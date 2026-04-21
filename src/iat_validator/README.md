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

# 5- Implementing IAT Code

1. GetModuleHandle

- What does it return?  
- What happens when you pass NULL as a parameter?  
- Which header do you need to include?


---

2. GetModuleInformation

- What is MODULEINFO and what fields does it have?  
- Why does it need a process handle as a parameter?  
- Which header do you need to include?


---

3. IMAGE_IMPORT_DESCRIPTOR

- How many fields does this struct have?  
- Which field points to the DLL name?  
- Which field points to IAT?  
- Which field points to ILT?  
- How do you know you've reached the end of the descriptor array?


---

4. IMAGE_THUNK_DATA

- What does each entry in this struct represent?  
- What is the difference between its value before and after Windows loads the executable?

---

Reference: 
- https://learn.microsoft.com/pt-br/windows/win32/api/libloaderapi/ (Microsoft Windows - API Documentation)





