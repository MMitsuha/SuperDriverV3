#pragma once

#include "Includes.h"
#include "Undisclosed.h"
#include "IRPCtlFile.h"

#define DELAY_ONE_MICROSECOND ( -10 )
#define DELAY_ONE_MILLISECOND ( DELAY_ONE_MICROSECOND * 1000 )

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define PTR_SUB_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Offset)))

NTSTATUS GetDriverObjectByName(
	IN PDRIVER_OBJECT* DriverObject,
	IN PWCHAR DriverName
);

/************************************************/

PUCHAR _PsGetProcessNameByProcessID(
	IN HANDLE PID
);

PUNICODE_STRING GetFilePathByFileObject(
	IN PFILE_OBJECT FileObject
);

/*************************************************/

BOOLEAN _ZwHideProcess(
	IN HANDLE PID
);

NTSTATUS _ZwOpenProcess(
	IN HANDLE PID,
	OUT PHANDLE hProcess
);

NTSTATUS _ZwTerminateProcess(
	IN HANDLE hProcess
);

NTSTATUS _ZwKillProcess(
	IN HANDLE PID
);

NTSTATUS _ZwSuperKillProcess(
	IN BOOLEAN IsCC,
	IN HANDLE PID
);

/**************************************************/
/*
NTSTATUS _ZwKillThread(
	IN HANDLE TID
);
*/
/**************************************************/

NTSTATUS _ZwSuperDeleteFile(
	IN PWCHAR wstrDeletePathName
);

NTSTATUS _ZwDeleteFile(
	IN PWCHAR wstrFileName
);

NTSTATUS _ZwCopyFile(
	IN PCWSTR wstrWriteFilePath,
	IN PCWSTR wstrReadFilePath
);

/***************************************************/

NTSTATUS AddSelfToSafeMode(
	IN CONST UNICODE_STRING ustrRegistryPath
);

NTSTATUS DelSelfFromSafeMode(
	IN CONST UNICODE_STRING ustrRegistryPath
);

/***************************************************/

PWCHAR PCHARToPWCHAR(
	IN CONST PCHAR Sur
);

PCHAR PWCHARToPCHAR(
	IN CONST PWCHAR Sur
);

/******************************************************/

VOID RemoveWP(
	OUT PKIRQL pirQl
);

VOID RecoveryWP(
	IN PKIRQL pirQl
);

/*********************************************************/

NTSTATUS GetDiskMiniport(
	IN OUT PDEVICE_OBJECT* DeviceObject,
	IN PUNICODE_STRING uniDeviceName
);

/***************************************************************************************/

NTSTATUS Sleep(
	IN UINT64 MilliSecond
);

/***************************************************************************************/

ULONG MessageBox(
	PWSTR MessageString,
	PWSTR MessageTitle,
	ULONG ShowOpt,
	ULONG ResponseOption,
	PNTSTATUS pntStatus OPTIONAL
);