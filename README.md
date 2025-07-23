# mnemosyne

A modern C++17 header-only library for direct Windows syscall invocation and PEB (Process Environment Block) manipulation. **mnemosyne** provides a clean, efficient interface for low-level Windows system programming while maintaining type safety and performance.

## features

- **Direct syscall invocation**: Bypass Windows API layers by calling syscalls directly
- **PEB walking**: Navigate the Process Environment Block to enumerate loaded modules
- **Dynamic SSN resolution**: Automatically extract System Service Numbers (SSNs) from NTDLL exports
- **Header-only design**: Easy integration with zero configuration
- **Hash-based lookups**: Fast module and function resolution using DJB2 hashing
- **Memory-mapped syscall stub**: Efficient syscall execution with runtime SSN patching
- **Type-safe interface**: Template-based design with compile-time optimizations

## requirements

- **Compiler**: Any C++17-supported compiler should work
- **Platform**: Windows (x86/x64)
- **Dependencies**: Windows SDK headers (`windows.h`, `winternl.h`, `ntstatus.h`)

## quick start

### installation

Simply include the header file in your project:

```cpp
#include "mnemosyne.hpp"
```
### basic usage
```cpp
#include <cstdio>
#include "mnemosyne.hpp"

int main() {
    mnemosyne::syscall::initialize();
    printf("[>] loaded syscalls: %zu\n", mnemosyne::detail::get_syscall_table().size());
    
    auto ntdll = mnemosyne::peb::get_module(DJB2(L"ntdll.dll"));
    auto kernel32 = mnemosyne::peb::get_module(DJB2("kernel32.dll"));
    
    printf("[>] ntdll.dll: 0x%p\n", ntdll);
    printf("[>] kernel32.dll: 0x%p\n", kernel32);
    
    SYSTEM_BASIC_INFORMATION sbi = {};
    ULONG return_length = 0;
    
    auto status = mnemosyne::syscall::invoke<NTSTATUS>(
        "NtQuerySystemInformation",
        SystemBasicInformation,
        &sbi,
        sizeof(sbi),
        &return_length
    );
    
    if (status == STATUS_SUCCESS) {
        printf("[>] number of processors: %d\n", static_cast<int>(sbi.NumberOfProcessors));
    } else {
        printf("[!] NtQuerySystemInformation failed with status: 0x%08X\n", status);
    }
    
    return 0;
}
```
### another example
```cpp
#include <cstdio>
#include "../include/mnemosyne.hpp"

int main() {
    mnemosyne::syscall::initialize();

    HANDLE file_handle = nullptr;
    OBJECT_ATTRIBUTES obj_attr = {};
    IO_STATUS_BLOCK io_status = {};
    UNICODE_STRING file_path = {};

    const wchar_t* path = L"\\??\\C:\\Windows\\Temp\\mnemosyne_test.txt";
    file_path.Buffer = const_cast<wchar_t*>(path);
    file_path.Length = static_cast<USHORT>(wcslen(path) * sizeof(wchar_t));
    file_path.MaximumLength = file_path.Length + sizeof(wchar_t);

    obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
    obj_attr.ObjectName = &file_path;
    obj_attr.Attributes = OBJ_CASE_INSENSITIVE;
    obj_attr.RootDirectory = nullptr;
    obj_attr.SecurityDescriptor = nullptr;
    obj_attr.SecurityQualityOfService = nullptr;

    auto status = mnemosyne::syscall::invoke<NTSTATUS>(
        "NtCreateFile",
        &file_handle,
        GENERIC_WRITE | SYNCHRONIZE,
        &obj_attr,
        &io_status,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0
    );

    if (status == STATUS_SUCCESS) {
        printf("[>] file created successfully, handle: 0x%p\n", file_handle);

        const char* test_data = "hello from mnemosyne syscall!\n";
        IO_STATUS_BLOCK write_io = {};

        auto write_status = mnemosyne::syscall::invoke<NTSTATUS>(
            "NtWriteFile",
            file_handle,
            nullptr,
            nullptr,
            nullptr,
            &write_io,
            const_cast<char*>(test_data),
            static_cast<ULONG>(strlen(test_data)),
            nullptr,
            nullptr
        );

        if (write_status == STATUS_SUCCESS) {
            printf("[>] wrote %lu bytes to file\n", write_io.Information);
        }
        else {
            printf("[!] write failed with status: 0x%08X\n", write_status);
        }

        mnemosyne::syscall::invoke<NTSTATUS>("NtClose", file_handle);
        printf("[>] file handle closed\n");
    }
    else {
        printf("[!] file creation failed with status: 0x%08X\n", status);
    }

    return 0;
}
```

## license
This project is provided for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## disclaimer
This software is provided "as is" without warranty. The authors assume no responsibility for any misuse or damage resulting from the use of this library. Use at your own risk and ensure compliance with all applicable laws and organizational policies.
