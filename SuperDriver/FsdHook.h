#pragma once

#include "Includes.h"
#include "Functions.h"
#include "DataList.h"
#include "Gobal.h"
#include "Undisclosed.h"

typedef NTSTATUS(*IRP_MJ_SERIES)
(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

typedef struct _IRP_COMPLETION_CONTEXT
{
	PIO_COMPLETION_ROUTINE CompletionRoutine;
	PVOID Context;
}IRP_COMPLETION_CONTEXT, * PIRP_COMPLETION_CONTEXT;

//------------------------------------

NTSTATUS FsdHook_HookTEST(
	VOID
);

//----------------------------------

NTSTATUS FsdHook_HookKeyboardRead(
	VOID
);

VOID FsdHook_UnhookKeyboardRead(
	VOID
);

//-----------------------------------

NTSTATUS FsdHook_HookNtfsDirectoryControl(
	VOID
);

VOID FsdHook_UnhookNtfsDirectoryControl(
	VOID
);

//-------------------------------------

NTSTATUS FsdHook_HookNtfsCreate(
	VOID
);

VOID FsdHook_UnhookNtfsCreate(
	VOID
);

//-------------------------------------------

NTSTATUS FsdHook_HookNtfsSetIfm(
	VOID
);

VOID FsdHook_UnhookNtfsSetIfm(
	VOID
);