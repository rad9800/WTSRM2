#include "wtrsm2.hpp"

#pragma comment(linker, "/ENTRY:entry")

int entry(const PPEB peb)
{
	wtsrm2_init(peb);

	ExitProcess(0);
}
