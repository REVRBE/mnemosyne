#ifndef MNEMOSYNE_HPP
#define MNEMOSYNE_HPP

#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstdint>
#include <type_traits>
#include <random>

#define DJB2(str) (mnemosyne::detail::djb2_hash(str))

namespace mnemosyne {
    namespace detail {

        template<typename T, std::size_t N = 1024>
        struct hash_table {
            struct entry {
                std::uint32_t key = 0;
                T value{};
                bool occupied = false;
            };

            entry buckets[N]{};

            void insert(std::uint32_t key, const T& value) noexcept {
                auto index = key % N;
                while (buckets[index].occupied && buckets[index].key != key) {
                    index = (index + 1) % N;
                }
                buckets[index].key = key;
                buckets[index].value = value;
                buckets[index].occupied = true;
            }

            T* find(std::uint32_t key) noexcept {
                auto index = key % N;
                while (buckets[index].occupied) {
                    if (buckets[index].key == key) {
                        return &buckets[index].value;
                    }
                    index = (index + 1) % N;
                }
                return nullptr;
            }
        };

        template<typename char_t>
        constexpr std::uint32_t djb2_hash(const char_t* str) noexcept {
            std::uint32_t hash = 5381;
            while (*str) {
                char_t c = *str++;
                if constexpr (sizeof(char_t) == 1) {
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
        __forceinline std::uint32_t djb2_hash_runtime(const char_t* str) noexcept {
            std::uint32_t hash = 5381;
            while (*str && *str != char_t(0)) {
                char_t c = *str++;
                if constexpr (sizeof(char_t) == 1) {
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

        template<std::size_t N>
        struct fixed_string {
            char data[N];
            std::size_t length;

            fixed_string() : length(0) {
                data[0] = '\0';
            }
        };

        template<std::size_t N>
        struct fixed_wstring {
            wchar_t data[N];
            std::size_t length;

            fixed_wstring() : length(0) {
                data[0] = L'\0';
            }
        };

        template<std::size_t N>
        __forceinline bool wide_to_narrow(const wchar_t* wide_str, fixed_string<N>& result) noexcept {
            if (!wide_str) return false;
            const int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, nullptr, 0, nullptr, nullptr);
            if (size_needed <= 0 || size_needed > N) return false;

            result.length = size_needed - 1;
            WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, result.data, size_needed, nullptr, nullptr);
            return true;
        }

        template<std::size_t N>
        __forceinline bool narrow_to_wide(const char* narrow_str, fixed_wstring<N>& result) noexcept {
            if (!narrow_str) return false;
            const int size_needed = MultiByteToWideChar(CP_UTF8, 0, narrow_str, -1, nullptr, 0);
            if (size_needed <= 0 || size_needed > N) return false;

            result.length = size_needed - 1;
            MultiByteToWideChar(CP_UTF8, 0, narrow_str, -1, result.data, size_needed);
            return true;
        }

        struct syscall_entry_t {
            std::uint32_t ssn;
            void* syscall_address;
            void* function_address;
        };

        inline hash_table<syscall_entry_t>& get_syscall_table() noexcept {
            static hash_table<syscall_entry_t> syscall_table;
            return syscall_table;
        }

        __forceinline std::uint32_t get_random_seed() noexcept {
            static thread_local std::random_device rd;
            static thread_local std::mt19937 gen(rd());
            static thread_local std::uniform_int_distribution<std::uint32_t> dist;

            return dist(gen);
        }

        __forceinline std::uint8_t construct_byte(std::uint8_t target_byte) noexcept {
            auto random_val = get_random_seed();
            auto method = random_val % 6;

            switch (method) {
            case 0: {
                auto a = static_cast<std::uint8_t>(random_val % (target_byte + 1));
                return a + (target_byte - a);
            }
            case 1: {
                auto a = static_cast<std::uint8_t>((random_val % 128) + target_byte);
                return (a >= target_byte) ? a - (a - target_byte) : target_byte;
            }
            case 2: {
                auto a = static_cast<std::uint8_t>(random_val % 256);
                return a ^ (a ^ target_byte);
            }
            case 3: {
                auto low_nibble = target_byte & 0x0F;
                auto high_nibble = (target_byte & 0xF0) >> 4;
                return (high_nibble << 4) | low_nibble;
            }
            case 4: {
                if (target_byte >= 2) {
                    auto a = static_cast<std::uint8_t>(random_val % (target_byte / 2));
                    return a + (target_byte - a);
                }
                return target_byte;
            }
            default:
                return target_byte ^ 0xFF ^ 0xFF;
            }
        }

        struct stub_variant_info {
            std::uint8_t size;
            std::uint8_t ssn_offset;
        };

        __forceinline stub_variant_info build_stub_variant(std::uint8_t* buffer, std::uint32_t variant_id) noexcept {

            const std::uint8_t variants[3][6] = {
                {0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00},
                {0x90, 0x4C, 0x8B, 0xD1, 0xB8, 0x00},
                {0x50, 0x58, 0x4C, 0x8B, 0xD1, 0xB8}
            };

            const stub_variant_info info[3] = {
                {4, 4}, {5, 5}, {6, 6}
            };

            const auto variant = variant_id % 3;
            const auto variant_info = info[variant];

            for (std::uint8_t i = 0; i < variant_info.size; ++i) {
                buffer[i] = construct_byte(variants[variant][i]);
            }

            return variant_info;
        }

        __forceinline constexpr bool is_syscall_instruction(const void* address) noexcept {
            if (!address) return false;
            const auto bytes = static_cast<const std::uint8_t*>(address);
            return (bytes[0] == 0x0F && (bytes[1] == 0x05 || bytes[1] == 0x34));
        }

        __forceinline const void* find_syscall_instruction(const void* function_address) noexcept {
            if (!function_address) return nullptr;
            const auto bytes = static_cast<const std::uint8_t*>(function_address);
            for (std::uint32_t i = 0; i < 0x50; ++i) {
                if (is_syscall_instruction(&bytes[i])) {
                    return &bytes[i];
                }
            }
            return nullptr;
        }

        __forceinline std::uint32_t extract_ssn(const void* function_address) noexcept {
            if (!function_address) return 0;
            const auto bytes = static_cast<const std::uint8_t*>(function_address);
            for (std::uint32_t i = 0; i < 0x20; ++i) {
                if (bytes[i] == 0xB8) {
                    return *reinterpret_cast<const std::uint32_t*>(&bytes[i + 1]);
                }
            }
            return 0;
        }

        __forceinline void* get_export_address(void* module_base, const char* function_name) noexcept {
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

        __forceinline void parse_module_exports(void* module_base) noexcept {
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

                if (!((function_name[0] == 'N' && function_name[1] == 't') ||
                    (function_name[0] == 'Z' && function_name[1] == 'w'))) {
                    continue;
                }

                const auto function_address = static_cast<std::uint8_t*>(module_base) + functions[ordinals[i]];
                const auto syscall_address = find_syscall_instruction(function_address);

                if (syscall_address) {
                    const auto ssn = extract_ssn(function_address);
                    if (ssn != 0) {
                        const auto hash = djb2_hash_runtime(function_name);
                        syscall_table.insert(hash, {
                            ssn,
                            const_cast<void*>(syscall_address),
                            function_address
                            });
                    }
                }
            }
        }

        template<typename return_type, typename... args_t>
        __forceinline return_type execute_syscall(std::uint32_t ssn, args_t... args);
    }

    namespace peb {
        __forceinline PEB* get_peb() noexcept {
#ifdef _WIN64
            return reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
            return reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
        }

        __forceinline void* get_module(std::uint32_t hash) noexcept {
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

                    if (detail::djb2_hash_runtime(filename) == hash)
                        return entry->DllBase;
                }

                current = current->Flink;
            }

            return nullptr;
        }

        __forceinline void* get_module(const char* module_name) {
            detail::fixed_wstring<260> wide_str;
            if (!detail::narrow_to_wide(module_name, wide_str)) return nullptr;
            return get_module(detail::djb2_hash(wide_str.data));
        }

        __forceinline void* get_module(const wchar_t* module_name) {
            return get_module(detail::djb2_hash(module_name));
        }

        template<typename callback_t>
        __forceinline void enumerate_modules(callback_t&& callback) noexcept {
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

        struct stub_cache {
            void* stub_memory = nullptr;
            bool initialized = false;
        };

        inline stub_cache& get_stub_cache() noexcept {
            static thread_local stub_cache cache{};
            return cache;
        }

        __forceinline void* generate_dynamic_stub() {
            auto ntdll_base = peb::get_module(DJB2(L"ntdll.dll"));
            if (!ntdll_base) return nullptr;

            auto nt_create_section = reinterpret_cast<NTSTATUS(NTAPI*)(
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)>(
                    get_export_address(ntdll_base, "NtCreateSection"));

            if (!nt_create_section) return nullptr;

            LARGE_INTEGER section_size{};
            section_size.QuadPart = 4096;

            OBJECT_ATTRIBUTES obj_attr{};
            obj_attr.Length = sizeof(obj_attr);

            HANDLE section_handle = nullptr;

            auto status = nt_create_section(&section_handle, SECTION_ALL_ACCESS, &obj_attr,
                &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

            if (status != STATUS_SUCCESS) return nullptr;

            auto nt_map_view = reinterpret_cast<NTSTATUS(NTAPI*)(
                HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG)>(
                    get_export_address(ntdll_base, "NtMapViewOfSection"));

            if (!nt_map_view) return nullptr;

            void* stub_memory = nullptr;
            SIZE_T view_size = 0;
            status = nt_map_view(section_handle, reinterpret_cast<HANDLE>(-1), &stub_memory,
                0, 0, nullptr, &view_size, 1, 0, PAGE_EXECUTE_READWRITE);

            if (status != STATUS_SUCCESS) return nullptr;

            return stub_memory;
        }

        template<typename return_type, typename... args_t>
        __forceinline return_type execute_syscall(std::uint32_t ssn, args_t... args) {
            auto& cache = get_stub_cache();

            if (!cache.initialized) {
                cache.stub_memory = generate_dynamic_stub();
                cache.initialized = true;
            }

            if (!cache.stub_memory) return return_type{};

            auto stub_bytes = static_cast<std::uint8_t*>(cache.stub_memory);
            auto random_variant = get_random_seed();
            auto variant_info = build_stub_variant(stub_bytes, random_variant);

            *reinterpret_cast<std::uint32_t*>(stub_bytes + variant_info.ssn_offset) = ssn;

            stub_bytes[variant_info.ssn_offset + 4] = construct_byte(0x0F);
            stub_bytes[variant_info.ssn_offset + 5] = construct_byte(0x05);
            stub_bytes[variant_info.ssn_offset + 6] = construct_byte(0xC3);

            auto func = reinterpret_cast<return_type(NTAPI*)(args_t...)>(stub_bytes);
            return func(args...);
        }
    }

    namespace syscall {
        __forceinline void initialize() noexcept {
            peb::enumerate_modules([](LDR_DATA_TABLE_ENTRY* entry) -> bool {
                if (entry->DllBase) {
                    detail::parse_module_exports(entry->DllBase);
                }
                return true;
                });
        }

        template<typename function_id_t>
        __forceinline detail::syscall_entry_t* get_syscall_entry(function_id_t function_identifier) noexcept {
            std::uint32_t hash;

            if constexpr (std::is_same_v<function_id_t, std::uint32_t>) {
                hash = function_identifier;
            }
            else if constexpr (std::is_same_v<function_id_t, const char*>) {
                hash = detail::djb2_hash_runtime(function_identifier);
            }
            else if constexpr (std::is_same_v<function_id_t, const wchar_t*>) {
                detail::fixed_string<512> narrow_str;
                if (!detail::wide_to_narrow(function_identifier, narrow_str)) return nullptr;
                hash = detail::djb2_hash_runtime(narrow_str.data);
            }
            else {
                static_assert(std::is_same_v<function_id_t, std::uint32_t> ||
                    std::is_same_v<function_id_t, const char*> ||
                    std::is_same_v<function_id_t, const wchar_t*>,
                    "Unsupported function identifier type");
            }

            auto& syscall_table = detail::get_syscall_table();
            return syscall_table.find(hash);
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
