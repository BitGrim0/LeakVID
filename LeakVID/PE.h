#pragma once
#include <ntifs.h>
#include <ntimage.h>

PIMAGE_FILE_HEADER GetFileHeader(void* Address);
void* HookIAT(void* BaseAddress, const char* Import, void* FunctionAddress);