#include <cstdio>
#include <chrono>
#include <vector>
#include "../include/mnemosyne.hpp"
#include "mnemosyne_mem.hpp"

int main() {
    printf("[>] initializing mnemosyne syscall table...\n");
    mnemosyne::syscall::initialize();
    printf("[>] syscall table initialized successfully\n\n");

    printf("[>] searching for notepad.exe process...\n");
    auto process_info = mnemosyne_mem::get_process_info(L"notepad.exe", PROCESS_ALL_ACCESS);

    if (process_info.pid == 0) {
        printf("[!] notepad.exe not found. please start notepad and try again.\n");
        return 1;
    }

    printf("[>] found notepad.exe with pid: %u\n", process_info.pid);

    if (!process_info.handle) {
        printf("[!] failed to open handle to notepad.exe\n");
        return 1;
    }

    printf("[>] successfully opened handle to notepad.exe: 0x%p\n\n", process_info.handle);

    printf("[>] finding writable memory region...\n");
    void* target_memory = nullptr;
    std::uintptr_t address = 0x10000;

    while (address < 0x7FFFFFFFFFFF) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (mnemosyne_mem::query_virtual_memory(process_info.handle, reinterpret_cast<void*>(address), mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
                mbi.RegionSize >= 4096) {
                target_memory = mbi.BaseAddress;
                break;
            }
            address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        else {
            address += 0x1000;
        }
    }

    if (!target_memory) {
        printf("[!] no writable memory region found\n");
        mnemosyne_mem::close_handle(process_info.handle);
        return 1;
    }

    printf("[>] using memory region: 0x%p\n\n", target_memory);

    constexpr std::uint32_t iterations = 100000;
    constexpr std::size_t buffer_size = 1024;
    std::vector<std::uint8_t> buffer(buffer_size, 0xAB);

    printf("[>] testing syscall read performance (%u iterations)...\n", iterations);
    auto start = std::chrono::high_resolution_clock::now();

    std::uint32_t syscall_read_success = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        auto result = mnemosyne_mem::read_virtual_memory(process_info.handle, target_memory, buffer.data(), buffer_size);
        if (result.success) syscall_read_success++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto syscall_read_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("[>] syscall read: %u/%u successful, %lld microseconds total\n", syscall_read_success, iterations, syscall_read_time);
    printf("[>] syscall read: %.2f microseconds per operation\n\n", static_cast<double>(syscall_read_time) / iterations);

    printf("[>] testing winapi read performance (%u iterations)...\n", iterations);
    start = std::chrono::high_resolution_clock::now();

    std::uint32_t winapi_read_success = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        SIZE_T bytes_read = 0;
        BOOL result = ReadProcessMemory(process_info.handle, target_memory, buffer.data(), buffer_size, &bytes_read);
        if (result) winapi_read_success++;
    }

    end = std::chrono::high_resolution_clock::now();
    auto winapi_read_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("[>] winapi read: %u/%u successful, %lld microseconds total\n", winapi_read_success, iterations, winapi_read_time);
    printf("[>] winapi read: %.2f microseconds per operation\n\n", static_cast<double>(winapi_read_time) / iterations);

    printf("[>] testing syscall write performance (%u iterations)...\n", iterations);
    start = std::chrono::high_resolution_clock::now();

    std::uint32_t syscall_write_success = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        auto result = mnemosyne_mem::write_virtual_memory(process_info.handle, target_memory, buffer.data(), buffer_size);
        if (result.success) syscall_write_success++;
    }

    end = std::chrono::high_resolution_clock::now();
    auto syscall_write_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("[>] syscall write: %u/%u successful, %lld microseconds total\n", syscall_write_success, iterations, syscall_write_time);
    printf("[>] syscall write: %.2f microseconds per operation\n\n", static_cast<double>(syscall_write_time) / iterations);

    printf("[>] testing winapi write performance (%u iterations)...\n", iterations);
    start = std::chrono::high_resolution_clock::now();

    std::uint32_t winapi_write_success = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        SIZE_T bytes_written = 0;
        BOOL result = WriteProcessMemory(process_info.handle, target_memory, buffer.data(), buffer_size, &bytes_written);
        if (result) winapi_write_success++;
    }

    end = std::chrono::high_resolution_clock::now();
    auto winapi_write_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("[>] winapi write: %u/%u successful, %lld microseconds total\n", winapi_write_success, iterations, winapi_write_time);
    printf("[>] winapi write: %.2f microseconds per operation\n\n", static_cast<double>(winapi_write_time) / iterations);

    double read_speedup = static_cast<double>(winapi_read_time) / syscall_read_time;
    double write_speedup = static_cast<double>(winapi_write_time) / syscall_write_time;

    printf("[>] performance comparison:\n");
    printf("[>] syscall read is %.2fx %s than winapi read\n",
        read_speedup > 1.0 ? read_speedup : 1.0 / read_speedup,
        read_speedup > 1.0 ? "faster" : "slower");
    printf("[>] syscall write is %.2fx %s than winapi write\n\n",
        write_speedup > 1.0 ? write_speedup : 1.0 / write_speedup,
        write_speedup > 1.0 ? "faster" : "slower");

    printf("[>] cleaning up...\n");
    if (mnemosyne_mem::close_handle(process_info.handle)) {
        printf("[>] handle closed successfully\n");
    }
    else {
        printf("[!] failed to close handle\n");
    }

    printf("\n[>] performance test completed successfully!\n");
    return 0;
}