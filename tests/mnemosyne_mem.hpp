// mnemosyne_mem.hpp
#ifndef MNEMOSYNE_MEM_HPP
#define MNEMOSYNE_MEM_HPP

#include "../include/mnemosyne.hpp"
#include <vector>
#include <cstring>

namespace mnemosyne_mem {

    struct process_info {
        std::uint32_t pid = 0;
        wchar_t process_name[260]{};
        HANDLE handle = nullptr;
    };

    struct memory_result {
        bool success = false;
        std::size_t bytes_transferred = 0;
        NTSTATUS status = 0;
    };

    __forceinline std::uint32_t get_process_id_by_name(const wchar_t* process_name) noexcept {
        if (!process_name) return 0;

        std::vector<std::uint8_t> buffer(0x10000);
        ULONG return_length = 0;

        auto status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtQuerySystemInformation"),
            SystemProcessInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &return_length
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(return_length);
            status = mnemosyne::syscall::invoke<NTSTATUS>(
                DJB2("NtQuerySystemInformation"),
                SystemProcessInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &return_length
            );
        }

        if (status != STATUS_SUCCESS) return 0;

        auto process_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer.data());

        while (true) {
            if (process_info->ImageName.Buffer && process_info->ImageName.Length > 0) {
                if (_wcsicmp(process_info->ImageName.Buffer, process_name) == 0) {
                    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(process_info->UniqueProcessId));
                }
            }

            if (process_info->NextEntryOffset == 0) break;
            process_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
                reinterpret_cast<std::uint8_t*>(process_info) + process_info->NextEntryOffset
                );
        }

        return 0;
    }

    __forceinline HANDLE open_process(std::uint32_t pid, ACCESS_MASK desired_access = PROCESS_ALL_ACCESS) noexcept {
        if (pid == 0) return nullptr;

        HANDLE process_handle = nullptr;
        OBJECT_ATTRIBUTES obj_attr{};
        CLIENT_ID client_id{};

        obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);
        client_id.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid));

        auto status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtOpenProcess"),
            &process_handle,
            desired_access,
            &obj_attr,
            &client_id
        );

        return (status == STATUS_SUCCESS) ? process_handle : nullptr;
    }

    __forceinline memory_result read_virtual_memory(HANDLE process_handle, void* base_address, void* buffer, std::size_t size) noexcept {
        memory_result result{};

        if (!process_handle || !base_address || !buffer || size == 0) {
            result.status = STATUS_INVALID_PARAMETER;
            return result;
        }

        SIZE_T bytes_read = 0;
        result.status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtReadVirtualMemory"),
            process_handle,
            base_address,
            buffer,
            size,
            &bytes_read
        );

        result.success = (result.status == STATUS_SUCCESS);
        result.bytes_transferred = bytes_read;
        return result;
    }

    __forceinline memory_result write_virtual_memory(HANDLE process_handle, void* base_address, const void* buffer, std::size_t size) noexcept {
        memory_result result{};

        if (!process_handle || !base_address || !buffer || size == 0) {
            result.status = STATUS_INVALID_PARAMETER;
            return result;
        }

        SIZE_T bytes_written = 0;
        result.status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtWriteVirtualMemory"),
            process_handle,
            base_address,
            const_cast<void*>(buffer),
            size,
            &bytes_written
        );

        result.success = (result.status == STATUS_SUCCESS);
        result.bytes_transferred = bytes_written;
        return result;
    }

    __forceinline bool close_handle(HANDLE handle) noexcept {
        if (!handle || handle == INVALID_HANDLE_VALUE) return false;

        auto status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtClose"),
            handle
        );

        return (status == STATUS_SUCCESS);
    }

    __forceinline process_info get_process_info(const wchar_t* process_name, ACCESS_MASK desired_access = PROCESS_ALL_ACCESS) noexcept {
        process_info info{};

        info.pid = get_process_id_by_name(process_name);
        if (info.pid != 0) {
            info.handle = open_process(info.pid, desired_access);
            wcsncpy_s(info.process_name, process_name, _TRUNCATE);
        }

        return info;
    }

    __forceinline bool query_virtual_memory(HANDLE process_handle, void* base_address, MEMORY_BASIC_INFORMATION& mbi) noexcept {
        if (!process_handle || !base_address) return false;

        SIZE_T return_length = 0;
        auto status = mnemosyne::syscall::invoke<NTSTATUS>(
            DJB2("NtQueryVirtualMemory"),
            process_handle,
            base_address,
            0,
            &mbi,
            sizeof(mbi),
            &return_length
        );

        return (status == STATUS_SUCCESS);
    }

    template<typename T>
    __forceinline bool read_memory(HANDLE process_handle, void* address, T& value) noexcept {
        auto result = read_virtual_memory(process_handle, address, &value, sizeof(T));
        return result.success;
    }

    template<typename T>
    __forceinline bool write_memory(HANDLE process_handle, void* address, const T& value) noexcept {
        auto result = write_virtual_memory(process_handle, address, &value, sizeof(T));
        return result.success;
    }
}

#endif