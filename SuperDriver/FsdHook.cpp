#include "FsdHook.h"

PVOID MapIrpBuffer(
	IN PIRP Irp
)
{
	TRY_START

		if (Irp->MdlAddress)
			return MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		else
			if (Irp->UserBuffer)
				return Irp->UserBuffer;
			else
				return Irp->AssociatedIrp.SystemBuffer;

	TRY_END(NULL)
}

PVOID InitIrpHook(
	IN PDRIVER_OBJECT DriverObject,
	IN ULONG IrpIndex,
	IN PVOID ProxyFunc
)
{
	ULONG64 RetIrp = 0;

	TRY_START

		volatile PLONG64 HookPoint = NULL;
	if (MmIsAddressValid(DriverObject))
	{
		HookPoint = (PLONG64)(&DriverObject->MajorFunction[IrpIndex]);
		RetIrp = InterlockedExchange64(HookPoint, (LONG64)ProxyFunc);
	}

	TRY_END((PVOID)RetIrp)
}

/********************模板************************/

IRP_MJ_SERIES g_OriginTESTDispatch = NULL;

NTSTATUS CurrentTESTDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	PEPROCESS pEProc = IoThreadToProcess(pIrp->Tail.Overlay.Thread);
	PWCHAR wstrProcName = PCHARToPWCHAR((PCHAR)PsGetProcessImageFileName(pEProc));
	if (IrpSp->Parameters.Write.ByteOffset.QuadPart / 512 == 0)
	{
		pIrp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_ACCESS_DENIED;
	}
	return g_OriginTESTDispatch(pDeviceObject, pIrp);
}

NTSTATUS FsdHook_HookTEST(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING uniDriveName = RTL_CONSTANT_STRING(L"\\Device\\Harddisk0\\DR0");
	PDEVICE_OBJECT pDeviceObject = NULL;
	PFILE_OBJECT pFileObject = NULL;
	IoGetDeviceObjectPointer(&uniDriveName, OBJ_OPENIF, &pFileObject, &pDeviceObject);
	if (NT_SUCCESS(ntStatus))
		//g_OriginTESTDispatch = (IRP_MJ_SERIES)InitIrpHook(pFileObject->DeviceObject->DriverObject, IRP_MJ_SET_INFORMATION, CurrentTESTDispatch);
		g_OriginTESTDispatch = (IRP_MJ_SERIES)InitIrpHook(pDeviceObject->DriverObject, IRP_MJ_WRITE, CurrentTESTDispatch);
	return ntStatus;
}

/*//--------------------------------------------------

PDRIVER_OBJECT g_KbdDrvObj = NULL;

IRP_MJ_SERIES g_OriginKbdReadDispatch = NULL;

INT iPendingIrps = 0;
PIRP pPendingIrp = NULL;

NTSTATUS CurrentKbdReadCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP pIrp,
	IN PVOID Context
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	__try
	{
		if (pIrp)
			if (MmIsAddressValid(pIrp))
			{
				if (NT_SUCCESS(pIrp->IoStatus.Status))
				{
					LPVOID Buffer = pIrp->AssociatedIrp.SystemBuffer;
					PKEYBOARD_INPUT_DATA KeyData = (PKEYBOARD_INPUT_DATA)Buffer;
					SIZE_T BufferLength = pIrp->IoStatus.Information;
					SIZE_T KeyNum = BufferLength / sizeof(KEYBOARD_INPUT_DATA);
					KdPrint(("[+] [HOOK_KBD] ScanCode:%x\n", KeyData->MakeCode));
					for (SIZE_T i = 0; i < KeyNum; ++i)
					{
						if (List_CheckNoWildcard(&g_KillKeyList, &(KeyData->MakeCode), sizeof(KeyData->MakeCode)))
						{
							RtlZeroMemory(KeyData, sizeof(*KeyData));
							ntStatus = STATUS_ACCESS_DENIED;
							pIrp->IoStatus.Status = ntStatus;
						}
					}
				}

				iPendingIrps--;

				if (pIrp->PendingReturned)
					IoMarkIrpPending(pIrp);

				if ((pIrp->StackCount > 1) && (Context != NULL))
					return ((PIO_COMPLETION_ROUTINE)Context)(DeviceObject, pIrp, NULL);
				else
					return pIrp->IoStatus.Status;
			}
	}
	__except (1)
	{
		KdPrint(("[-] [HOOK_KBD] Fail!\n"));
	}
	return ntStatus;
}

NTSTATUS CurrentKbdReadDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(pIrp);

	irpSp->Control =
		SL_INVOKE_ON_SUCCESS |
		SL_INVOKE_ON_ERROR |
		SL_INVOKE_ON_CANCEL;

	//irpSp->Control = SL_INVOKE_ON_SUCCESS;
	//保留原来的完成函数，如果有的话
	irpSp->Context = irpSp->CompletionRoutine;
	irpSp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)CurrentKbdReadCompletion;

	iPendingIrps++;
	if (iPendingIrps > 0)
	{
		pPendingIrp = pIrp;
	}

	return g_OriginKbdReadDispatch(pDeviceObject, pIrp);
}

BOOLEAN CancelKeyboardIrp(
	IN PIRP Irp
)
{
	if (Irp == NULL)
		return FALSE;

	//
	// 这里有些判断应该不是必须的，不过还是小心点好
	//
	if (Irp->Cancel || Irp->CancelRoutine == NULL)
		return FALSE;

	if (FALSE == IoCancelIrp(Irp))
		return FALSE;

	//
	// 取消后重设此例程为空
	//
	IoSetCancelRoutine(Irp, NULL);
	return TRUE;
}

NTSTATUS FsdHook_HookKeyboardRead(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if (!(MmIsAddressValid(g_KbdDrvObj) && g_KbdDrvObj))
		ntStatus = GetDriverObjectByName(&g_KbdDrvObj, L"\\Driver\\Kbdclass");
	if (NT_SUCCESS(ntStatus) && MmIsAddressValid(g_KbdDrvObj) && g_KbdDrvObj)
		g_OriginKbdReadDispatch = (IRP_MJ_SERIES)InitIrpHook(g_KbdDrvObj, IRP_MJ_READ, CurrentKbdReadDispatch);

	if (iPendingIrps > 0 && pPendingIrp != NULL)
		if (CancelKeyboardIrp(pPendingIrp) == STATUS_CANCELLED)
			KdPrint(("[+] Cancel Irp Success!\n"));
		else
			KdPrint(("[-] Cancel Irp Fail!\n"));

	iPendingIrps = 0;
	pPendingIrp = NULL;

	return ntStatus;
}

VOID FsdHook_UnhookKeyboardRead(
	VOID
)
{
	if (MmIsAddressValid(g_KbdDrvObj) && g_KbdDrvObj)
	{
		InitIrpHook(g_KbdDrvObj, IRP_MJ_READ, g_OriginKbdReadDispatch);
		g_OriginKbdReadDispatch = NULL;
		ObDereferenceObject(g_KbdDrvObj);
		g_KbdDrvObj = NULL;
	}
}*/

//-------------------------------------------------

PDRIVER_OBJECT g_KbdDrvObj = NULL;

IRP_MJ_SERIES g_OriginKbdReadDispatch = NULL;

INT iPendingIrps = 0;
PIRP pPendingIrp = NULL;

NTSTATUS CurrentKbdReadCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP pIrp,
	IN PVOID Context
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		if (pIrp)
		{
			if (NT_SUCCESS(pIrp->IoStatus.Status))
			{
				PKEYBOARD_INPUT_DATA KeyData = (PKEYBOARD_INPUT_DATA)pIrp->AssociatedIrp.SystemBuffer;
				SIZE_T BufferLength = pIrp->IoStatus.Information;
				SIZE_T KeyNum = BufferLength / sizeof(KEYBOARD_INPUT_DATA);
				for (SIZE_T i = 0; i < KeyNum; ++i)
				{
					PrintIfm("[HOOK_KBD] Status:%s ,ScanCode:%X\n", KeyData->Flags ? "UP" : "DOWN", KeyData->MakeCode);
					if (List_CheckNoWildcard(&g_KillKeyList, &(KeyData->MakeCode), sizeof(KeyData->MakeCode)))
					{
						RtlZeroMemory(KeyData, sizeof(*KeyData));
						ntStatus = STATUS_ACCESS_DENIED;
						pIrp->IoStatus.Status = ntStatus;
					}
					++KeyData;
				}
			}

			iPendingIrps--;

			if (pIrp->PendingReturned)
				IoMarkIrpPending(pIrp);

			if ((pIrp->StackCount > 1) && (Context != NULL))
				return ((PIO_COMPLETION_ROUTINE)Context)(DeviceObject, pIrp, NULL);
			else
				return pIrp->IoStatus.Status;
		}

	TRY_END(ntStatus)
}

NTSTATUS CurrentKbdReadDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	TRY_START

		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(pIrp);

	irpSp->Control =
		SL_INVOKE_ON_SUCCESS |
		SL_INVOKE_ON_ERROR |
		SL_INVOKE_ON_CANCEL;

	//irpSp->Control = SL_INVOKE_ON_SUCCESS;
	//保留原来的完成函数，如果有的话
	irpSp->Context = irpSp->CompletionRoutine;
	irpSp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)CurrentKbdReadCompletion;

	iPendingIrps++;
	if (iPendingIrps > 0)
	{
		pPendingIrp = pIrp;
	}

	TRY_END(g_OriginKbdReadDispatch(pDeviceObject, pIrp))
}

BOOLEAN CancelKeyboardIrp(
	IN PIRP Irp
)
{
	TRY_START

		if (Irp == NULL)
			return FALSE;

	//
	// 这里有些判断应该不是必须的，不过还是小心点好
	//
	if (Irp->Cancel || Irp->CancelRoutine == NULL)
		return FALSE;

	if (FALSE == IoCancelIrp(Irp))
		return FALSE;

	//
	// 取消后重设此例程为空
	//
	IoSetCancelRoutine(Irp, NULL);
	return TRUE;

	TRY_END(FALSE)
}

NTSTATUS FsdHook_HookKeyboardRead(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (!g_KbdDrvObj)
		ntStatus = GetDriverObjectByName(&g_KbdDrvObj, L"\\Driver\\Kbdclass");
	if (NT_SUCCESS(ntStatus) && g_KbdDrvObj)
		g_OriginKbdReadDispatch = (IRP_MJ_SERIES)InitIrpHook(g_KbdDrvObj, IRP_MJ_READ, CurrentKbdReadDispatch);

	if (iPendingIrps > 0 && pPendingIrp != NULL)
		if (CancelKeyboardIrp(pPendingIrp) == STATUS_CANCELLED)
			PrintSuc("Cancel Irp Success!\n");
		else
			PrintErr("Cancel Irp Fail!\n");

	iPendingIrps = 0;
	pPendingIrp = NULL;

	return ntStatus;
}

VOID FsdHook_UnhookKeyboardRead(
	VOID
)
{
	if (g_KbdDrvObj)
	{
		InitIrpHook(g_KbdDrvObj, IRP_MJ_READ, g_OriginKbdReadDispatch);
		g_OriginKbdReadDispatch = NULL;
		ObDereferenceObject(g_KbdDrvObj);
		g_KbdDrvObj = NULL;
	}

	return;
}

/******************************************************************************************************/

PDRIVER_OBJECT g_NtfsDrvObj = NULL;

IRP_MJ_SERIES g_OriginNtfsDirectoryControlDispatch = NULL;
IRP_MJ_SERIES g_OriginNtfsCreateDispatch = NULL;
IRP_MJ_SERIES g_OriginNtfsSetIfmDispatch = NULL;

NTSTATUS CurrentNtfsDirectoryControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		if (pIrp)
		{
			PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
			PEPROCESS pEProc = IoThreadToProcess(pIrp->Tail.Overlay.Thread);
			HANDLE PID = PsGetProcessId(pEProc);
			PUNICODE_STRING uniDirPath = NULL;
			PUNICODE_STRING puniProcImageName = NULL;
			ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
			if (!NT_SUCCESS(ntStatus))
			{
				PrintErr("[HOOK_SETIFM] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
				return STATUS_UNSUCCESSFUL;
			}

			if (IrpSp->FileObject)
				uniDirPath = GetFilePathByFileObject(IrpSp->FileObject);

			if (uniDirPath)
			{
				PrintIfm("[HOOK_DIRCTL] ProcPath:%wZ ,ProcID:%I64u ,TargetDir:%wZ ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, uniDirPath, pEProc);

				if (List_CheckNoWildcard(&g_ProtDirList, (LPVOID)uniDirPath->Buffer, uniDirPath->Length))
				{
					PVOID pBuffer = MapIrpBuffer(pIrp);
					RtlZeroMemory(pBuffer, pIrp->IoStatus.Information);
					ntStatus = STATUS_ACCESS_DENIED;
					pIrp->IoStatus.Status = ntStatus;
					IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				}
				else
					ntStatus = g_OriginNtfsDirectoryControlDispatch(pDeviceObject, pIrp);
			}
			else
				PrintIfm("[HOOK_DIRCTL] ProcPath:%wZ ,ProcID:%I64u ,TargetDir:UNKNOWN ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, pEProc);
		}

	TRY_END(ntStatus);
}

NTSTATUS FsdHook_HookNtfsDirectoryControl(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	TRY_START

		if (!g_NtfsDrvObj)
			ntStatus = GetDriverObjectByName(&g_NtfsDrvObj, L"\\FileSystem\\Ntfs");
	if (NT_SUCCESS(ntStatus) && g_NtfsDrvObj)
		g_OriginNtfsDirectoryControlDispatch = (IRP_MJ_SERIES)InitIrpHook(g_NtfsDrvObj, IRP_MJ_DIRECTORY_CONTROL, CurrentNtfsDirectoryControlDispatch);

	TRY_END(ntStatus)
}

VOID FsdHook_UnhookNtfsDirectoryControl(
	VOID
)
{
	TRY_START

		if (g_NtfsDrvObj)
		{
			InitIrpHook(g_NtfsDrvObj, IRP_MJ_DIRECTORY_CONTROL, g_OriginNtfsDirectoryControlDispatch);
			g_OriginNtfsDirectoryControlDispatch = NULL;
			if (!(g_OriginNtfsCreateDispatch || g_OriginNtfsSetIfmDispatch))
			{
				ObDereferenceObject(g_NtfsDrvObj);
				g_NtfsDrvObj = NULL;
			}
		}

	TRY_END_NOSTATUS
}

//----------------------------------------------------------------------------------------------

NTSTATUS CurrentNtfsCreateDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		if (pIrp)
		{
			PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
			PEPROCESS pEProc = IoThreadToProcess(pIrp->Tail.Overlay.Thread);
			HANDLE PID = PsGetProcessId(pEProc);
			PUNICODE_STRING uniDirPath = NULL;
			PUNICODE_STRING puniProcImageName = NULL;
			ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
			if (!NT_SUCCESS(ntStatus))
			{
				PrintErr("[HOOK_SETIFM] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
				return STATUS_UNSUCCESSFUL;
			}

			if (IrpSp->FileObject)
				uniDirPath = GetFilePathByFileObject(IrpSp->FileObject);

			if (uniDirPath)
			{
				PrintIfm("[HOOK_CREATE] ProcPath:%wZ ,ProcID:%I64u ,TargetFile:%wZ ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, uniDirPath, pEProc);
				if (List_CheckNoWildcard(&g_ProtDirList, (LPVOID)uniDirPath->Buffer, uniDirPath->Length))
				{
					PVOID pBuffer = MapIrpBuffer(pIrp);
					RtlZeroMemory(pBuffer, pIrp->IoStatus.Information);
					ntStatus = STATUS_ACCESS_DENIED;
					pIrp->IoStatus.Status = ntStatus;
					IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				}
				else
					ntStatus = g_OriginNtfsCreateDispatch(pDeviceObject, pIrp);
			}
			else
				PrintIfm("[HOOK_CREATE] ProcPath:%wZ ,ProcID:%I64u ,TargetFile:UNKNOWN ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, pEProc);
		}

	TRY_END(ntStatus);
}

NTSTATUS FsdHook_HookNtfsCreate(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	TRY_START

		if (!g_NtfsDrvObj)
			ntStatus = GetDriverObjectByName(&g_NtfsDrvObj, L"\\FileSystem\\Ntfs");
	if (NT_SUCCESS(ntStatus) && g_NtfsDrvObj)
		g_OriginNtfsCreateDispatch = (IRP_MJ_SERIES)InitIrpHook(g_NtfsDrvObj, IRP_MJ_CREATE, CurrentNtfsCreateDispatch);

	TRY_END(ntStatus)
}

VOID FsdHook_UnhookNtfsCreate(
	VOID
)
{
	TRY_START

		if (g_NtfsDrvObj)
		{
			InitIrpHook(g_NtfsDrvObj, IRP_MJ_CREATE, g_OriginNtfsCreateDispatch);
			g_OriginNtfsCreateDispatch = NULL;
			if (!(g_OriginNtfsDirectoryControlDispatch || g_OriginNtfsSetIfmDispatch))
			{
				ObDereferenceObject(g_NtfsDrvObj);
				g_NtfsDrvObj = NULL;
			}
		}

	TRY_END_NOSTATUS
}

//----------------------------------------------------------------------------------------------

NTSTATUS CurrentNtfsSetIfmDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		if (pIrp)
		{
			PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
			PEPROCESS pEProc = IoThreadToProcess(pIrp->Tail.Overlay.Thread);
			HANDLE PID = PsGetProcessId(pEProc);
			PUNICODE_STRING uniDirPath = NULL;
			PUNICODE_STRING puniProcImageName = NULL;
			ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
			if (!NT_SUCCESS(ntStatus))
			{
				PrintErr("[HOOK_SETIFM] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
				return STATUS_UNSUCCESSFUL;
			}

			if (IrpSp->FileObject)
				uniDirPath = GetFilePathByFileObject(IrpSp->FileObject);

			if (uniDirPath)
			{
				PrintIfm("[HOOK_SETIFM] ProcPath:%wZ ,ProcID:%I64u ,TargetFile:%wZ ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, uniDirPath, pEProc);
				if (List_CheckNoWildcard(&g_ProtDirList, (LPVOID)uniDirPath->Buffer, uniDirPath->Length))
				{
					PVOID pBuffer = MapIrpBuffer(pIrp);
					RtlZeroMemory(pBuffer, pIrp->IoStatus.Information);
					ntStatus = STATUS_ACCESS_DENIED;
					pIrp->IoStatus.Status = ntStatus;
					IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				}
				else
					ntStatus = g_OriginNtfsSetIfmDispatch(pDeviceObject, pIrp);
			}
			else
				PrintIfm("[HOOK_SETIFM] ProcPath:%wZ ,ProcID:%I64u ,TargetFile:UNKNOWN ,ProcAddr:%p\n", puniProcImageName, (UINT64)PID, pEProc);
		}

	TRY_END(ntStatus)
}

NTSTATUS FsdHook_HookNtfsSetIfm(
	VOID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	TRY_START

		if (!g_NtfsDrvObj)
			ntStatus = GetDriverObjectByName(&g_NtfsDrvObj, L"\\FileSystem\\Ntfs");
	if (NT_SUCCESS(ntStatus) && g_NtfsDrvObj)
		g_OriginNtfsSetIfmDispatch = (IRP_MJ_SERIES)InitIrpHook(g_NtfsDrvObj, IRP_MJ_SET_INFORMATION, CurrentNtfsSetIfmDispatch);

	TRY_END(ntStatus)
}

VOID FsdHook_UnhookNtfsSetIfm(
	VOID
)
{
	TRY_START

		if (g_NtfsDrvObj)
		{
			InitIrpHook(g_NtfsDrvObj, IRP_MJ_SET_INFORMATION, g_OriginNtfsSetIfmDispatch);
			g_OriginNtfsCreateDispatch = NULL;
			if (!(g_OriginNtfsDirectoryControlDispatch || g_OriginNtfsDirectoryControlDispatch))
			{
				ObDereferenceObject(g_NtfsDrvObj);
				g_NtfsDrvObj = NULL;
			}
		}

	TRY_END_NOSTATUS
}