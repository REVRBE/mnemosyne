#ifndef MNEMOSYNE_HPP
#define MNEMOSYNE_HPP

#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstdint>
#include <unordered_map>
#include <string>

#define DJB2(str) (mnemosyne::detail::djb2_hash(str))

namespace mnemosyne {
    namespace detail {
        template<typename char_t>
        constexpr std::uint32_t djb2_hash(const char_t* str) {
            std::uint32_t hash = 5381;
            while (*str) {
                char_t c = *str++;
                if (sizeof(char_t) == 1) {
                    if (c >= 'A' && c <= 'Z')
                        c += 32;
                }
                else {
                    if (c >= L'A' && c <= L'Z')
                        c += 32;
                }
                hash = ((hash << 5) + hash) + c;
            }
            return hash;
        }

        template<typename char_t>
        __forceinline std::uint32_t djb2_hash_runtime(const char_t* str) {
            std::uint32_t hash = 5381;
            while (*str && *str != char_t(0)) {
                char_t c = *str++;
                if (sizeof(char_t) == 1) {
                    if (c >= 'A' && c <= 'Z')
                        c += 32;
                }
                else {
                    if (c >= L'A' && c <= L'Z')
                        c += 32;
                }
                hash = ((hash << 5) + hash) + c;
            }
            return hash;
        }

        __forceinline std::string wide_to_narrow(const wchar_t* wide_str) {
            if (!wide_str) return {};
            const int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, nullptr, 0, nullptr, nullptr);
            if (size_needed <= 0) return {};
            std::string result(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, &result[0], size_needed, nullptr, nullptr);
            return result;
        }

        __forceinline std::wstring narrow_to_wide(const char* narrow_str) {
            if (!narrow_str) return {};
            const int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow_str, -1, nullptr, 0);
            if (size_needed <= 0) return {};
            std::wstring result(size_needed - 1, 0);
            MultiByteToWideChar(CP_UTF8, 0, narrow_str, -1, &result[0], size_needed);
            return result;
        }

        struct syscall_entry_t {
            std::uint32_t ssn;
            void* syscall_address;
            void* function_address;
        };

        inline std::unordered_map<std::uint32_t, syscall_entry_t>& get_syscall_table() {
            static std::unordered_map<std::uint32_t, syscall_entry_t> syscall_table;
            return syscall_table;
        }

        __forceinline bool is_syscall_instruction(void* address) {
            if (!address) return false;
            const auto bytes = static_cast<std::uint8_t*>(address);
            return (bytes[0] == 0x0F && (bytes[1] == 0x05 || bytes[1] == 0x34));
        }

        __forceinline void* find_syscall_instruction(void* function_address) {
            if (!function_address) return nullptr;
            const auto bytes = static_cast<std::uint8_t*>(function_address);
            for (std::uint32_t i = 0; i < 0x50; ++i) {
                if (is_syscall_instruction(&bytes[i])) {
                    return &bytes[i];
                }
            }
            return nullptr;
        }

        __forceinline std::uint32_t extract_ssn(void* function_address) {
            if (!function_address) return 0;
            const auto bytes = static_cast<std::uint8_t*>(function_address);
            for (std::uint32_t i = 0; i < 0x20; ++i) {
                if (bytes[i] == 0xB8) {
                    return *reinterpret_cast<std::uint32_t*>(&bytes[i + 1]);
                }
            }
            return 0;
        }

        __forceinline void* get_export_address(void* module_base, const char* function_name) {
            if (!module_base || !function_name) return nullptr;

            const auto dos_header = static_cast<IMAGE_DOS_HEADER*>(module_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

            const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                static_cast<std::uint8_t*>(module_base) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return nullptr;

            const auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!export_dir_rva) return nullptr;

            const auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                static_cast<std::uint8_t*>(module_base) + export_dir_rva);

            const auto names = reinterpret_cast<std::uint32_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfNames);
            const auto functions = reinterpret_cast<std::uint32_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfFunctions);
            const auto ordinals = reinterpret_cast<std::uint16_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfNameOrdinals);

            const auto target_hash = djb2_hash_runtime(function_name);

            for (std::uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
                const auto export_name = reinterpret_cast<const char*>(
                    static_cast<std::uint8_t*>(module_base) + names[i]);

                if (djb2_hash_runtime(export_name) == target_hash) {
                    return static_cast<std::uint8_t*>(module_base) + functions[ordinals[i]];
                }
            }
            return nullptr;
        }

        __forceinline void parse_module_exports(void* module_base) {
            if (!module_base) return;

            const auto dos_header = static_cast<IMAGE_DOS_HEADER*>(module_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return;

            const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                static_cast<std::uint8_t*>(module_base) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return;

            const auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!export_dir_rva) return;

            const auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                static_cast<std::uint8_t*>(module_base) + export_dir_rva);

            const auto names = reinterpret_cast<std::uint32_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfNames);
            const auto functions = reinterpret_cast<std::uint32_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfFunctions);
            const auto ordinals = reinterpret_cast<std::uint16_t*>(
                static_cast<std::uint8_t*>(module_base) + export_dir->AddressOfNameOrdinals);

            auto& syscall_table = get_syscall_table();

            for (std::uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
                const auto function_name = reinterpret_cast<const char*>(
                    static_cast<std::uint8_t*>(module_base) + names[i]);

                if ((function_name[0] == 'N' && function_name[1] == 't') ||
                    (function_name[0] == 'Z' && function_name[1] == 'w')) {

                    const auto function_address = static_cast<std::uint8_t*>(module_base) + functions[ordinals[i]];
                    const auto syscall_address = find_syscall_instruction(function_address);

                    if (syscall_address) {
                        const auto ssn = extract_ssn(function_address);
                        if (ssn != 0) {
                            const auto hash = djb2_hash_runtime(function_name);
                            syscall_table[hash] = {
                                ssn,
                                syscall_address,
                                function_address
                            };
                        }
                    }
                }
            }
        }

        template<typename return_type, typename... args_t>
        __forceinline return_type execute_syscall(std::uint32_t ssn, args_t... args);
    }

    namespace peb {
        __forceinline PEB* get_peb() {
#ifdef _WIN64
            return reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
            return reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
        }

        __forceinline void* get_module(std::uint32_t hash) {
            const auto peb = get_peb();
            if (!peb || !peb->Ldr)
                return nullptr;

            const auto head = &peb->Ldr->InMemoryOrderModuleList;
            auto current = head->Flink;

            while (current && current != head) {
                const auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
                    wchar_t* filename = nullptr;
                    for (int i = entry->FullDllName.Length / sizeof(wchar_t) - 1; i >= 0; --i) {
                        if (entry->FullDllName.Buffer[i] == L'\\') {
                            filename = &entry->FullDllName.Buffer[i + 1];
                            break;
                        }
                    }

                    if (!filename)
                        filename = entry->FullDllName.Buffer;

                    std::uint32_t current_hash = detail::djb2_hash_runtime(filename);

                    if (current_hash == hash)
                        return entry->DllBase;
                }

                current = current->Flink;
            }

            return nullptr;
        }

        __forceinline void* get_module(const char* module_name) {
            auto wide_str = detail::narrow_to_wide(module_name);
            return get_module(detail::djb2_hash(wide_str.c_str()));
        }

        __forceinline void* get_module(const wchar_t* module_name) {
            return get_module(detail::djb2_hash(module_name));
        }

        template<typename callback_t>
        __forceinline void enumerate_modules(callback_t&& callback) {
            const auto peb = get_peb();
            if (!peb || !peb->Ldr)
                return;

            const auto head = &peb->Ldr->InMemoryOrderModuleList;
            auto current = head->Flink;

            while (current && current != head) {
                const auto entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (!callback(entry))
                    break;

                current = current->Flink;
            }
        }
    }

    namespace detail {

        inline void* g_syscall_stub = nullptr;

        __forceinline void* get_syscall_stub() {
            if (!g_syscall_stub) {

                auto ntdll_base = peb::get_module(DJB2(L"ntdll.dll"));
                if (!ntdll_base) return nullptr;

                auto nt_create_section = reinterpret_cast<NTSTATUS(NTAPI*)(
                    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)>(
                        get_export_address(ntdll_base, "NtCreateSection"));

                if (!nt_create_section) return nullptr;

                LARGE_INTEGER section_size;
                section_size.QuadPart = 4096;

                OBJECT_ATTRIBUTES obj_attr = {};
                obj_attr.Length = sizeof(obj_attr);

                HANDLE section_handle = nullptr;

                auto status = nt_create_section(&section_handle, SECTION_ALL_ACCESS, &obj_attr,
                    &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

                if (status != STATUS_SUCCESS) return nullptr;

                auto nt_map_view = reinterpret_cast<NTSTATUS(NTAPI*)(
                    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG)>(
                        get_export_address(ntdll_base, "NtMapViewOfSection"));

                if (!nt_map_view) return nullptr;

                SIZE_T view_size = 0;
                status = nt_map_view(section_handle, reinterpret_cast<HANDLE>(-1), &g_syscall_stub,
                    0, 0, nullptr, &view_size, 1, 0, PAGE_EXECUTE_READWRITE);

                if (status != STATUS_SUCCESS) return nullptr;

                auto stub_bytes = static_cast<std::uint8_t*>(g_syscall_stub);
                stub_bytes[0] = 0x4C; stub_bytes[1] = 0x8B; stub_bytes[2] = 0xD1;
                stub_bytes[3] = 0xB8;
                stub_bytes[4] = 0x00; stub_bytes[5] = 0x00; stub_bytes[6] = 0x00; stub_bytes[7] = 0x00;
                stub_bytes[8] = 0x0F; stub_bytes[9] = 0x05;
                stub_bytes[10] = 0xC3;
            }
            return g_syscall_stub;
        }

        template<typename return_type, typename... args_t>
        __forceinline return_type execute_syscall(std::uint32_t ssn, args_t... args) {
            auto stub = get_syscall_stub();
            if (!stub) return return_type{};

            *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(stub) + 4) = ssn;

            auto func = reinterpret_cast<return_type(NTAPI*)(args_t...)>(stub);
            return func(args...);
        }
    }

    namespace syscall {
        __forceinline void initialize() {
            peb::enumerate_modules([](LDR_DATA_TABLE_ENTRY* entry) -> bool {
                if (entry->DllBase) {
                    detail::parse_module_exports(entry->DllBase);
                }
                return true;
                });
        }

        __forceinline detail::syscall_entry_t* get_syscall_entry(std::uint32_t hash) {
            auto& syscall_table = detail::get_syscall_table();
            auto it = syscall_table.find(hash);
            return (it != syscall_table.end()) ? &it->second : nullptr;
        }

        __forceinline detail::syscall_entry_t* get_syscall_entry(const char* function_name) {
            auto hash = detail::djb2_hash_runtime(function_name);
            return get_syscall_entry(hash);
        }

        __forceinline detail::syscall_entry_t* get_syscall_entry(const wchar_t* function_name) {
            auto narrow_str = detail::wide_to_narrow(function_name);
            return get_syscall_entry(narrow_str.c_str());
        }

        template<typename return_type = NTSTATUS, typename function_id_t, typename... args_t>
        __forceinline return_type invoke(function_id_t function_identifier, args_t... args) {
            const auto entry = get_syscall_entry(function_identifier);
            if (!entry) return STATUS_PROCEDURE_NOT_FOUND;

            return detail::execute_syscall<return_type>(entry->ssn, args...);
        }
    }
}

#endif