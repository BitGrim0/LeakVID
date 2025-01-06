#include "Log.h"
#include <ntdef.h>
#include <ntstatus.h>
#include <ntstrsafe.h>
#include <wdm.h>

NTSTATUS OpenLogFile(PHANDLE fileHandle)
{
	OBJECT_ATTRIBUTES attributes;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK ioStatusBlock;

	RtlInitUnicodeString(&fileName, LOG_FILE_PATH);
	InitializeObjectAttributes(&attributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	return ZwCreateFile(
		fileHandle,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&attributes,
		&ioStatusBlock,
		nullptr,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		nullptr,
		0
	);
}

NTSTATUS WriteLogFile(HANDLE fileHandle, PCSTR message)
{
	IO_STATUS_BLOCK ioStatusBlock;
	size_t logLength;

	RtlStringCbLengthA(message, 512, &logLength);

	return ZwWriteFile(
		fileHandle,
		nullptr,
		nullptr,
		nullptr,
		&ioStatusBlock,
		(PVOID)message,
		(ULONG)logLength,
		nullptr,
		nullptr
	);
}

void Log(const char* format, ...)
{
	HANDLE fileHandle;

	auto status = OpenLogFile(&fileHandle);

	if (!NT_SUCCESS(status)) return;

	char buffer[512];
	va_list args;
	va_start(args, format);
	RtlStringCbVPrintfA(buffer, sizeof(buffer), format, args);
	va_end(args);

	WriteLogFile(fileHandle, buffer);

	ZwClose(fileHandle);
}