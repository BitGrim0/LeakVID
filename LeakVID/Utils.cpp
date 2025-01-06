#include "Utils.h"

void CopyMemory(void* Dst, void* Src, size_t Size)
{
	auto const physicalAddress = MmGetPhysicalAddress(Dst);

	if (auto const virtualAddress = MmMapIoSpace(physicalAddress, Size, MmCached))
	{
		memcpy(virtualAddress, Src, Size);
		MmUnmapIoSpace(virtualAddress, Size);
	}
}

void* GetModuleBase(const char* szModule)
{
	ULONG bytes{};
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return nullptr;

	auto modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);

	if (!modules)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(modules);
		return nullptr;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	void* moduleBase = nullptr;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), szModule) == 0)
		{
			moduleBase = module[i].ImageBase;
			break;
		}
	}

	ExFreePool(modules);

	return moduleBase;
}

void DumpMemory(void* Address, unsigned Length)
{
	if (!Address || !Length) return;

	HANDLE             fileHandle;
	UNICODE_STRING     name;
	OBJECT_ATTRIBUTES  attributes;
	IO_STATUS_BLOCK    statusBlock;
	LARGE_INTEGER      offset{ NULL };

	RtlInitUnicodeString(&name, L"\\DosDevices\\C:\\dump.bin");

	InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	auto status = ZwCreateFile(
		&fileHandle,
		GENERIC_WRITE,
		&attributes,
		&statusBlock,
		nullptr,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		NULL
	);

	status = ZwWriteFile(
		fileHandle,
		nullptr,
		nullptr,
		nullptr,
		&statusBlock,
		Address,
		Length,
		&offset,
		nullptr
	);

	ZwClose(fileHandle);
}