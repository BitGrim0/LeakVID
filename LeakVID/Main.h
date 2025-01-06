#pragma once
#include <ntifs.h>
#include <intrin.h>

#define VID_TIMESTAMP 0x5284EAC3

typedef struct _COPY_MEMORY_BUFFER_INFO
{
	ULONGLONG case_number;
	ULONGLONG reserved;
	void* source;
	void* destination;
	ULONGLONG length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef union _VirtualAddressT
{
	void* value;
	struct
	{
		ULONG64 offset : 12;
		ULONG64 pt_index : 9;
		ULONG64 pd_index : 9;
		ULONG64 pdpt_index : 9;
		ULONG64 pml4_index : 9;
		ULONG64 reserved : 16;
	};
} VirtualAddressT, * PVirtualAddressT;