#include "DriverDispatch.h"

#define UNVERIFIED -1
#define VERIFIED 0
#define UNKNOWN 1

BOOLEAN CreateStatus = FALSE;

INT VerificationStatus = UNVERIFIED;

NTSTATUS DefaultDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS CreateDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	if (CreateStatus)
		HalReturnToFirmware(HalPowerDownRoutine);

	CreateStatus = TRUE;

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS CloseDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	CreateStatus = FALSE;

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS IoControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
)
{
	ULONG_PTR Size = 0;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(pIrp);
	PVOID SystemBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ULONG InBufferLength = StackLocation->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutBufferLength = StackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (VerificationStatus != VERIFIED && ControlCode != CTL_DRIVER_VERIFICATION)
		HalReturnToFirmware(HalPowerDownRoutine);

	/*****************我还以为用了C++能不这么弄,结果还是要....*****************/
	HANDLE hProcess = NULL;
	/*********************************************************************/

	switch (ControlCode)
	{
		//DRIVER_CONTROL

		case CTL_ENABLE_KBD_HOOK:
			ntStatus = FsdHook_HookKeyboardRead();
			break;

		case CTL_DISABLE_KBD_HOOK:
			FsdHook_UnhookKeyboardRead();
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DISABLE_KBD_KEY:
			if (List_AddToTail(&g_KillKeyList, SystemBuffer, sizeof(USHORT)))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			Size = sizeof(USHORT);
			break;

		case CTL_ENABLE_KBD_KEY:
			if (List_DeleteNoWildcard(&g_KillKeyList, SystemBuffer, sizeof(USHORT)))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			Size = sizeof(USHORT);
			break;

		case CTL_EMPTY_KBD_KEY:
			List_DeleteAll(&g_KillKeyList);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_DIR_HOOK:
			ntStatus = FsdHook_HookNtfsDirectoryControl();
			break;

		case CTL_DISABLE_DIR_HOOK:
			FsdHook_UnhookNtfsDirectoryControl();
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_FILE_CREATE_HOOK:
			ntStatus = FsdHook_HookNtfsCreate();
			break;

		case CTL_DISABLE_FILE_CREATE_HOOK:
			FsdHook_UnhookNtfsCreate();
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_FILE_SETIFM_HOOK:
			ntStatus = FsdHook_HookNtfsSetIfm();
			break;

		case CTL_DISABLE_FILE_SETIFM_HOOK:
			FsdHook_UnhookNtfsSetIfm();
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_FILE_MON:
			ntStatus = Mon_CreateFileMon(TRUE);
			break;

		case CTL_DISABLE_FILE_MON:
			ntStatus = Mon_CreateFileMon(FALSE);
			break;

		case CTL_ADD_FILE_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			if (List_AddToTail(&g_ProtFileList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_DEL_FILE_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			if (List_DeleteNoWildcard(&g_ProtFileList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_EMPTY_FILE_WHITE_LIST:
			List_DeleteAll(&g_ProtFileList);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ADD_DIR_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			if (List_AddToTail(&g_ProtDirList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_DEL_DIR_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			if (List_DeleteNoWildcard(&g_ProtDirList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_EMPTY_DIR_WHITE_LIST:
			List_DeleteAll(&g_ProtDirList);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DELETE_FILE:
			ntStatus = _ZwDeleteFile((PWCHAR)SystemBuffer);
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			break;

		case CTL_SUPER_DELETE_FILE:
			ntStatus = _ZwSuperDeleteFile((PWCHAR)SystemBuffer);
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			break;

		case CTL_IRP_DELETE_FILE:
			ntStatus = IrpAutoDeleteFile((PWCHAR)SystemBuffer);
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			break;

		case CTL_IRP_PROTECT_FILE:
			ntStatus = IrpAutoProtectFile((PWCHAR)SystemBuffer);
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, USHRT_MAX / sizeof(WCHAR)) + 1);
			break;

			/*
		case CTL_ENABLE_PROC_MON:
			ntStatus = Mon_CreateProcMon(TRUE);
			break;

		case CTL_DISABLE_PROC_MON:
			ntStatus = Mon_CreateProcMon(FALSE);
			break;
			*/

		case CTL_ENABLE_PROC_MON_EX:
			ntStatus = Mon_CreateProcMonEx(TRUE);
			break;

		case CTL_DISABLE_PROC_MON_EX:
			ntStatus = Mon_CreateProcMonEx(FALSE);
			break;

		case CTL_ENABLE_PROC_MON_KILL:
			ntStatus = Mon_CreateProcKillMon(TRUE);
			break;

		case CTL_DISABLE_PROC_MON_KILL:
			ntStatus = Mon_CreateProcKillMon(FALSE);
			break;

		case CTL_ADD_PROC_BLACK_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, MAX_PATH) + 1);
			if (List_AddToTail(&g_KillProcList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_DEL_PROC_BLACK_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, MAX_PATH) + 1);
			if (List_DeleteNoWildcard(&g_KillProcList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_EMPTY_PROC_BLACK_LIST:
			List_DeleteAll(&g_KillProcList);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ADD_PROC_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, MAX_PATH) + 1);
			if (List_AddToTail(&g_ProtProcList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_DEL_PROC_WHITE_LIST:
			Size = sizeof(WCHAR) * (wcsnlen((PWCHAR)SystemBuffer, MAX_PATH) + 1);
			if (List_DeleteNoWildcard(&g_ProtProcList, SystemBuffer, Size))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			break;

		case CTL_EMPTY_PROC_WHITE_LIST:
			List_DeleteAll(&g_ProtProcList);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_KILL_ALL_PROC:
			g_KillAllProc_Switch = TRUE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DISABLE_KILL_ALL_PROC:
			g_KillAllProc_Switch = FALSE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_HIDE_PROC:
			if (_ZwHideProcess((HANDLE) * (PUINT64)SystemBuffer))
				ntStatus = STATUS_SUCCESS;
			else
				ntStatus = STATUS_UNSUCCESSFUL;
			Size = sizeof(*(PUINT64)SystemBuffer);
			break;

		case CTL_KILL_PROC:
			ntStatus = _ZwKillProcess((HANDLE) * (PUINT64)SystemBuffer);
			Size = sizeof(*(PUINT64)SystemBuffer);
			break;

		case CTL_KILL_PROC_EX:
			ntStatus = _ZwOpenProcess((HANDLE) * (PUINT64)SystemBuffer, &hProcess);
			if (NT_SUCCESS(ntStatus))
				ntStatus = _ZwTerminateProcess(hProcess);
			Size = sizeof(*(PUINT64)SystemBuffer);
			break;

		case CTL_SUPER_KILL_PROC_ZERO:
			ntStatus = _ZwSuperKillProcess(FALSE, (HANDLE) * (PUINT64)SystemBuffer);
			Size = sizeof(*(PUINT64)SystemBuffer);
			break;

		case CTL_SUPER_KILL_PROC_CC:
			ntStatus = _ZwSuperKillProcess(TRUE, (HANDLE) * (PUINT64)SystemBuffer);
			Size = sizeof(*(PUINT64)SystemBuffer);
			break;

		case CTL_ENABLE_THR_MON:
			ntStatus = Mon_CreateThrMon(TRUE);
			break;

		case CTL_DISABLE_THR_MON:
			ntStatus = Mon_CreateThrMon(FALSE);
			break;

			/*
		case CTL_ENABLE_KILL_ALL_THR:
			g_KillAllThr_Switch = TRUE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DISABLE_KILL_ALL_THR:
			g_KillAllThr_Switch = FALSE;
			ntStatus = STATUS_SUCCESS;
			break;
			*/

		case CTL_ENABLE_MOD_MON:
			ntStatus = Mon_CreateMoudleMon(TRUE);
			break;

		case CTL_DISABLE_MOD_MON:
			ntStatus = Mon_CreateMoudleMon(FALSE);
			break;

		case CTL_ENABLE_KILL_ALL_DLL:
			g_KillAllDll_Switch = TRUE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DISABLE_KILL_ALL_DLL:
			g_KillAllDll_Switch = FALSE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_KILL_ALL_SYS:
			g_KillAllSys_Switch = TRUE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DISABLE_KILL_ALL_SYS:
			g_KillAllSys_Switch = FALSE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_ENABLE_REG_MON:
			ntStatus = Mon_CreateRegMon(TRUE);
			break;

		case CTL_DISABLE_REG_MON:
			ntStatus = Mon_CreateRegMon(FALSE);
			break;

		case CTL_ENABLE_SAFEMODE_STRAT:
			ntStatus = AddSelfToSafeMode(g_uniRegistryPath);
			break;

		case CTL_DISABLE_SAFEMODE_STRAT:
			ntStatus = DelSelfFromSafeMode(g_uniRegistryPath);
			break;

		case CTL_PROTECT_SELF_REGISTRY:
			g_ProtSelfReg_Switch = TRUE;
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_SUPER_SHUTDOWN:
			HalReturnToFirmware(HalPowerDownRoutine);
			ntStatus = STATUS_SUCCESS;
			break;

		case CTL_DRIVER_VERIFICATION:
			if (InBufferLength >= sizeof(AuthorizationContext))
			{
				if (!memcmp(SystemBuffer, AuthorizationContext, InBufferLength))
				{
					VerificationStatus = VERIFIED;
					ntStatus = STATUS_SUCCESS;
				}
				else
					HalReturnToFirmware(HalPowerDownRoutine);
			}
			else
				ntStatus = STATUS_BUFFER_TOO_SMALL;
			Size = InBufferLength;
			break;

		default:
			PrintErr("[-] Unkonown Code:%ul\n", ControlCode);
			ntStatus = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	pIrp->IoStatus.Information = Size;
	pIrp->IoStatus.Status = ntStatus;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}