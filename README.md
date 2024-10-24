# Self-Run-PE

Self-Run-PE is a Windows-based process injection tool that allocates memory in a remote process and writes a copy of the current process's image into that memory. It uses direct system calls to perform the injection and execute code in the target process. This project demonstrates how to utilize low-level Windows APIs such as `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` to achieve process injection.

## Features

- **Process Injection**: Injects code into a target process by writing the current process's image into the target's memory space.
- **Base Relocation Fixing**: Handles base relocations to ensure the injected PE works correctly when mapped at a different base address.
- **Thread Execution**: Creates a remote thread in the target process to execute the injected code.

## Usage:
.\inject.exe notepad.exe

- Made by Evilbytecode aka Ebyte

## PoC:
![image](https://github.com/user-attachments/assets/18415099-2b78-4a7c-9dd3-ff90cf0ed3f6)
