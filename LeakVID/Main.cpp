#include "Main.h"
#include "Log.h"
#include "PE.h"
#include "Utils.h"

void* OriginalDeviceControl = nullptr;

NTSTATUS DeviceControlTemplate(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS HookedDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode == 0x80862007)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength)
		{
			auto buffer = static_cast<PCOPY_MEMORY_BUFFER_INFO>(stack->Parameters.SetFile.DeleteHandle);

			if (buffer->case_number == 0x33)
			{
				if (VirtualAddressT{ buffer->destination }.pml4_index > 255)
				{
					if (buffer->length > 0x100)
					{
						Log("[LeakVID] Copying memory 0x%p => 0x%p (0x%x)\n",
							buffer->source,
							buffer->destination,
							buffer->length
						);

						auto source = reinterpret_cast<DWORD_PTR>(buffer->source) - 0x1000;
						auto length = buffer->length + 0x1000;

						DumpMemory((PVOID)source, length);
					}
				}
			}
		}
	}

	return reinterpret_cast<decltype(&DeviceControlTemplate)>(OriginalDeviceControl)(DeviceObject, Irp);
}

NTSTATUS HookedIoCreateDevice(
	PDRIVER_OBJECT  DriverObject,
	ULONG           DeviceExtensionSize,
	PUNICODE_STRING DeviceName,
	DEVICE_TYPE     DeviceType,
	ULONG           DeviceCharacteristics,
	BOOLEAN         Exclusive,
	PDEVICE_OBJECT* DeviceObject)
{
	Log("[LeakVID] IoCreateDevice called\n");

	OriginalDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &HookedDeviceControl;

	Log("[LeakVID] DeviceControl hooked: 0x%p => 0x%p", OriginalDeviceControl, DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]);

	return IoCreateDevice(
		DriverObject,
		DeviceExtensionSize,
		DeviceName,
		DeviceType,
		DeviceCharacteristics,
		Exclusive,
		DeviceObject
	);
}

void OnImageLoad(PUNICODE_STRING ImagePath, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (ProcessId) return;

	auto fileHeader = GetFileHeader(ImageInfo->ImageBase);

	if (!fileHeader)
	{
		Log("[LeakVID] Failed to read FileHeader: %ws\n", ImagePath->Buffer);
		return;
	}

	bool isVID = fileHeader->TimeDateStamp == VID_TIMESTAMP;

	Log("[LeakVID] Driver loaded (Path: %ws, Timestamp: 0x%p, VID: %d)\n", ImagePath->Buffer, fileHeader->TimeDateStamp, isVID);

	if (isVID)
	{
		auto originalFunctionAddress = HookIAT(ImageInfo->ImageBase, "IoCreateDevice", &HookedIoCreateDevice);
		Log("[LeakVID] IoCreateDevice hooked: 0x%p => 0x%p\n", originalFunctionAddress, &HookedIoCreateDevice);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	Log("[LeakVID] Driver loaded.\n");

	PsSetLoadImageNotifyRoutine(OnImageLoad);

	Log("[LeakVID] Routine ready.\n");

	return 0;
}