#include "wtrsm2.hpp"

#pragma comment(linker, "/ENTRY:entry")

int entry(const PPEB peb)
{
	wtsrm2_init(peb);

	MessageBoxA(NULL, NULL, NULL, MB_OK);

	ExitProcess(0);
}
