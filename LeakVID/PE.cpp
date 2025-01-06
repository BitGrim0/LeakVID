#include "PE.h"
#include "Utils.h"
#include "Log.h"

bool IsValidPE(void* Address)
{
    return Address && *(short*)Address == 0x5A4D;
}

PIMAGE_FILE_HEADER GetFileHeader(void* Address)
{
    if (!IsValidPE(Address)) return nullptr;

    auto baseAddress = reinterpret_cast<DWORD_PTR>(Address);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);

    return &ntHeaders->FileHeader;
}

void* HookIAT(void* BaseAddress, const char* Import, void* FunctionAddress)
{
    if (!IsValidPE(BaseAddress) || !Import || !FunctionAddress) 
    {
        Log("[LeakVID] HookIAT: Not valid PE\n");
        return NULL;
    }

    auto baseAddress = reinterpret_cast<DWORD_PTR>(BaseAddress);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);
    auto importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(baseAddress + importDirectory.VirtualAddress);

    if (!importDescriptor) 
    {
        Log("[LeakVID] HookIAT: ImportDescriptor not found\n");
        return NULL;
    }

    while (importDescriptor->Name != NULL)
    {
        if (auto moduleName = baseAddress + (LPCSTR)importDescriptor->Name; GetModuleBase(moduleName))
        {
            auto originalFirstThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->OriginalFirstThunk);
            auto firstThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != NULL)
            {
                if (auto functionName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + originalFirstThunk->u1.AddressOfData); strcmp(functionName->Name, Import) == 0)
                {
                    auto originalFunctionAddress = reinterpret_cast<PVOID>(firstThunk->u1.Function);

                    CopyMemory(&firstThunk->u1.AddressOfData, &FunctionAddress, 8);

                    return originalFunctionAddress;
                }

                ++originalFirstThunk;
                ++firstThunk;
            }
        }

        ++importDescriptor;
    }

    Log("[LeakVID] HookIAT: Function not found\n");
    return NULL;
}