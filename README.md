## WTSRM2 
This is a continuation to my original project [WTSRM](https://github.com/rad9800/WTSRM) and the corresponding [talk.](https://www.youtube.com/watch?v=TfG9lBYCOq8)

This project was re-written in order to utilize C++17 in order to create a template that allows us to change the required functionality at compile time with ease! This is implemented as a header only file such that you can easily add it to your own projects.


Some of the features currently implemented include:
- No CRT dependencies (10KB binary)
- Unhook all Windows DLLs with either a '.text' patch using \KnownDlls\ or \System32\
- Use VirtualProtect or WriteProcessMemory for patching
- Compile time API hashing
- Remove and restore Vectored Exception Handlers 
- Remove Ldr DLL notification callbacks
- Clear hardware breakpoints
- Load libraries using work items

We can configure this behaviour as follows

```c
#define HASHING_ALGORITHM hash_string_fnv1a	// constexpr algorithm

namespace config
{
	...

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
```

As we utilize constexpr, we don't pay for the features we don't use as they're dead code and optimized out of the program.

## Using this header

To import DLLs first we must create the hash using the `DLL_HASH` macro
```c
DLL_HASH(DBGHELP, L"DBGHELP.DLL")
```

We then must add it to the module_address_table which acts as our internal IAT. The `hash_` constant is created by the DLL_HASH macro. For non-common DLLs which aren't always loaded we must specify their name so that we can load them.

```c
inline addr_struct<decltype(HASHING_ALGORITHM(TOKENIZEA(T))), wchar_t> module_address_table[] =
{
	{hash_NTDLL, nullptr,},
	{hash_KERNEL32, nullptr,},
	{hash_DBGHELP, nullptr, L"DBGHELP.DLL"}
};
```

To import functions, first we must create the function name hash and typedef using the `HASH_FUNC` macro
```c
HASH_FUNC(NtUnmapViewOfSection, NTSTATUS, HANDLE, PVOID)
```
The first parameter is the name of the function, next is the return type, and then the arguments to the function. We are then required to add it to our `api_address_table` which will be populated with the current function addresses

```c
inline addr_struct<decltype(HASHING_ALGORITHM(TOKENIZEA(T))), void> api_address_table[] =
{
	{hash_GetProcAddress, nullptr},		
	{hash_NtUnmapViewOfSection, nullptr},
```
If you fail to add this function to this table, the program will not crash, but will return -1 in an attempt to increase stability.

To use an API use use the `API()()` macro as demonstrated
```c
API(NtWaitForSingleObject)(NtCurrentProcess(), FALSE, &timeout);
```

To add your own API hashing function you must use this template in order to work with the required types.

```c
template <typename T>
constexpr auto hash_string_(const T* buffer)
{
	TRIVIAL_TYPE_CHECK()

}
```

Thank you to these individuals in no particular order for their ideas and contributions
[@peterwintrsmith](https://twitter.com/peterwintrsmith)
[@modexpblog](https://twitter.com/modexpblog)
[@jonaslyk](https://twitter.com/jonasLyk)
[@JustasMasiulis](https://twitter.com/JustasMasiulis)
