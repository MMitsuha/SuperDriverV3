#include "Monitor.h"

VOID ProcessCreateMonEx					//进程事件 回调处理函数
(
	__inout PEPROCESS EProcess,
	__in HANDLE ProcessID,
	__in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
) {
	TRY_START

		PEPROCESS pEProc = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(ProcessID, &pEProc);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON_EX] PsLookupProcessByProcessId Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	PUNICODE_STRING puniProcImageName = NULL;
	ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON_EX] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	ObDereferenceObject(pEProc);

	if (CreateInfo)			//进程创建事件
	{
		if (CreateInfo->IsSubsystemProcess == TRUE || CreateInfo->FileOpenNameAvailable == FALSE)
		{
			PrintErr("[PROC_MON_EX] 不满足过滤 ,回调退出!\n");
			return;
		}

		PrintIfm("[PROC_MON_EX] [CREATE] ProcPath:%wZ,%wZ ,ProcID:%I64u ,ParentProcID:%I64u ,CmdLine:%wZ ,ProcAddress:%p\n",
			CreateInfo->ImageFileName,
			puniProcImageName,
			(UINT64)ProcessID,
			(UINT64)CreateInfo->ParentProcessId,
			CreateInfo->CommandLine,
			EProcess
		);

		if (g_KillAllProc_Switch || List_CheckNoWildcard(&g_KillProcList, (LPVOID)puniProcImageName->Buffer, puniProcImageName->Length))
		{
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
			PrintSuc("[PROC_MON_EX] Terminal Process Success!\n");
		}
	}
	else
	{
		PrintIfm("[PROC_MON_EX] [TERMINAL] ProcPath:%wZ ,ProcID:%I64u ,ProcAddress:%p\n",
			puniProcImageName,
			(UINT64)ProcessID,
			EProcess
		);
	}

	TRY_END_NOSTATUS
}

NTSTATUS Mon_CreateProcMonEx(
	IN BOOLEAN bCreate
) {
	if (bCreate)
		return PsSetCreateProcessNotifyRoutineEx(ProcessCreateMonEx, FALSE);
	else
		return PsSetCreateProcessNotifyRoutineEx(ProcessCreateMonEx, TRUE);
}

//----------------------------------------------------------------------

VOID ProcessCreateMon(
	IN HANDLE hParentID,
	IN HANDLE ProcessID,
	IN BOOLEAN bCreate
) {
	TRY_START

		PEPROCESS pEProc = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(ProcessID, &pEProc);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON] PsLookupProcessByProcessId Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	PUNICODE_STRING puniProcImageName = NULL;
	ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	ObDereferenceObject(pEProc);

	if (bCreate)			//进程创建事件
	{
		PrintIfm("[PROC_MON] [CREATE] ProcPath:%wZ ,ProcID:%I64u ,ParentProcID:%I64u ,ProcAddress:%p\n",
			puniProcImageName,
			(UINT64)ProcessID,
			(UINT64)hParentID,
			pEProc
		);

		if (g_KillAllProc_Switch || List_CheckNoWildcard(&g_KillProcList, (LPVOID)puniProcImageName->Buffer, puniProcImageName->Length))
		{
			ntStatus = _ZwKillProcess(ProcessID);
			if (!NT_SUCCESS(ntStatus))
				PrintErr("[PROC_MON] Kill Process Fail! Errorcode:%X", ntStatus);
		}
	}
	else
	{
		PrintIfm("[PROC_MON] [TERMINAL] ProcPath:%wZ ,ProcID:%I64u ,ProcAddress:%p\n",
			puniProcImageName,
			(UINT64)ProcessID,
			pEProc
		);
	}

	TRY_END_NOSTATUS
}

NTSTATUS Mon_CreateProcMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
		return PsSetCreateProcessNotifyRoutine(ProcessCreateMon, FALSE);
	else
		//if (g_ntProcMonStatus)
		return PsSetCreateProcessNotifyRoutine(ProcessCreateMon, TRUE);
	//else
		//return STATUS_INVALID_PARAMETER;
}

//--------------------------------------------------------------------

PVOID GetDriverEntryByImageBase(//返回可执行映像 的执行入口地址
	IN PVOID ImageBase
) {
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS64 pNTHeader;
	PVOID pEntryPoint;
	pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;
	pNTHeader = (PIMAGE_NT_HEADERS64)((ULONG64)ImageBase + pDOSHeader->e_lfanew);
	pEntryPoint = (PVOID)((ULONG64)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
	return pEntryPoint;
}

BOOLEAN VxkCopyMemory(
	IN PVOID pDestination,
	IN PVOID pSourceAddress,
	IN SIZE_T SizeOfCopy
) {
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);//建立MDL内存
	if (!pMdl)
		return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);//锁定内存页
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);//释放
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);//Buffer映射到内核地址空间
	if (!pSafeAddress)
		return FALSE;
	RtlCopyMemory(pDestination, pSafeAddress, SizeOfCopy);//拷贝
	MmUnlockPages(pMdl);//解锁内存页
	IoFreeMdl(pMdl);//释放
	return TRUE;
}

VOID DenyLoadDriver(//在入口地址写入禁止执行的机器码
	IN PVOID pDriverEntry
) {
	UCHAR ExitCode[] = "\xB8\x22\x00\x00\xC0\xC3";
	if (MmIsAddressValid(pDriverEntry))
	{
		KIRQL irQl = 0;
		RemoveWP(&irQl);
		if (!VxkCopyMemory(pDriverEntry, ExitCode, sizeof(ExitCode)))
			PrintErr("[DenyLoadDriver] Fail!\n");
		RecoveryWP(&irQl);
	}
	return;
}

VOID DenyLoadDll(
	IN PVOID pLoadImageBase
)
{
	//BOOLEAN IsFail = TRUE;

	// DLL拒绝加载, 不能类似驱动那样直接在入口点返回拒绝加载信息. 这样达不到卸载DLL的效果.
	// 将文件头 前0x200 字节数据置零
	static CONST BYTE Empty[0x200] = { 0 };
	if (MmIsAddressValid(pLoadImageBase))
	{
		KIRQL irQl = 0;
		RemoveWP(&irQl);
		if (!VxkCopyMemory(pLoadImageBase, (LPVOID)Empty, sizeof(Empty)))
			//	PrintSuc("[DenyLoadDll] Success!\n");
			//else
			PrintErr("[DenyLoadDll] Fail!\n");
		RecoveryWP(&irQl);

		/*
		KIRQL irQl = 0;
		RemoveWP(&irQl);
		// 创建 MDL 方式修改内存
		PMDL pMdl = MmCreateMdl(NULL, pLoadImageBase, ulDataSize);
		if (NULL != pMdl)
		{
			MmBuildMdlForNonPagedPool(pMdl);
			PVOID pVoid = MmMapLockedPages(pMdl, KernelMode);
			if (NULL != pVoid)
			{
				IsFail = FALSE;
				// 置零
				RtlZeroMemory(pVoid, ulDataSize);
				// 释放 MDL
				MmUnmapLockedPages(pVoid, pMdl);
			}
			IoFreeMdl(pMdl);
		}
		RecoveryWP(&irQl);
		*/
	}
	/*
	if (IsFail)
		KdPrint(("[-] DenyLoadDll Fail!\n"));
	else
		KdPrint(("[+] DenyLoadDll Success!\n"));
	*/
	return;
}

VOID ImageLoadMon//模块加载 过滤函数
(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessID,
	IN PIMAGE_INFO ImageInfo
) {
	TRY_START

		if (FullImageName)
		{
			PIMAGE_INFO_EX pInfoEx = NULL;
			if (ImageInfo->ExtendedInfoPresent)
				pInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

			PVOID pEntry = GetDriverEntryByImageBase(ImageInfo->ImageBase);
			NTSTATUS ntStatus = STATUS_SUCCESS;

			if (ProcessID == 0 && ImageInfo->SystemModeImage)
			{
				PrintIfm("[IMAGE_MON] [SYS] ImageName:%wZ ,ImageEntry:%p\n", FullImageName, pEntry);
				if (pInfoEx)
				{
					if (!g_KillAllSys_Switch && !List_CheckNoWildcard(&g_KillSysList, FullImageName->Buffer, FullImageName->Length))
						return;
					HANDLE hThread = NULL;
					if (NT_SUCCESS(ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, DenyLoadDriver, pEntry)))
						ZwClose(hThread);
					else
						PrintErr("[IMAGE_MON] [SYS] Create Thread Fail! Errorcode:%X\n", ntStatus);
				}
			}
			else
			{
				HANDLE hThread = NULL;
				PEPROCESS pEProc = NULL;
				ntStatus = PsLookupProcessByProcessId(ProcessID, &pEProc);
				if (!NT_SUCCESS(ntStatus))
				{
					PrintErr("[IMAGE_MON] PsLookupProcessByProcessId Fail! Errorcode:%X\n", ntStatus);
					ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, DenyLoadDll, pEntry);
					if (NT_SUCCESS(ntStatus))
						ZwClose(hThread);
					else
						PrintErr("[IMAGE_MON] [DLL] Create Thread Fail! Errorcode:%X\n", ntStatus);
					return;
				}
				PUNICODE_STRING puniProcImageName = NULL;
				ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
				if (!NT_SUCCESS(ntStatus))
				{
					PrintErr("[IMAGE_MON] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
					ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, DenyLoadDll, pEntry);
					if (NT_SUCCESS(ntStatus))
						ZwClose(hThread);
					else
						PrintErr("[IMAGE_MON] [DLL] Create Thread Fail! Errorcode:%X\n", ntStatus);
					return;
				}
				ObDereferenceObject(pEProc);

				PrintIfm("[IMAGE_MON] [DLL] ProcPath:%wZ ,ImageName:%wZ ,ProcID:%I64u ,ImageEntry:%p\n", puniProcImageName, FullImageName, (UINT64)ProcessID, pEntry);
				//if (pInfoEx)
				//{
				if (!g_KillAllDll_Switch && !List_CheckNoWildcard(&g_KillDllList, FullImageName->Buffer, FullImageName->Length))
					return;
				ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, DenyLoadDll, pEntry);
				if (NT_SUCCESS(ntStatus))
					ZwClose(hThread);
				else
					PrintErr("[IMAGE_MON] [DLL] Create Thread Fail! Errorcode:%X\n", ntStatus);
				//}
			}
		}

	TRY_END_NOSTATUS
}

NTSTATUS Mon_CreateMoudleMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
		return PsSetLoadImageNotifyRoutine(ImageLoadMon);
	else
		//if (g_ntImageMonStatus)
		return PsRemoveLoadImageNotifyRoutine(ImageLoadMon);
	//else
		//return STATUS_INVALID_PARAMETER;
}

//--------------------------------------------------------------

VOID ThreadCreateMon(
	IN HANDLE PID,
	IN HANDLE TID,
	IN BOOLEAN bCreate
) {
	TRY_START

		PEPROCESS pEProc = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(PID, &pEProc);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[THREAD_MON] PsLookupProcessByProcessId Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	PUNICODE_STRING puniProcImageName = NULL;
	ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[THREAD_MON] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
		return;
	}
	ObDereferenceObject(pEProc);

	if (bCreate)
	{
		PrintIfm("[THREAD_MON] [CREATE] ProcPath:%wZ ,ProcID:%I64u ,ThreadID:%I64u\n",
			puniProcImageName,
			(UINT64)PID,
			(UINT64)TID
		);

		if (g_KillAllThr_Switch)
			//_ZwKillThread(TID);
			PrintErr("[THREAD_MON] 使用了未实现的功能!\n");
	}
	else
		PrintIfm("[THREAD_MON] [TERMINATED] ProcPath:%wZ ,ProcID:%I64u ,ThreadID:%I64u\n",
			puniProcImageName,
			(UINT64)PID,
			(UINT64)TID
		);

	TRY_END_NOSTATUS
}

NTSTATUS Mon_CreateThrMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
		return PsSetCreateThreadNotifyRoutine(ThreadCreateMon);
	else
		//if (g_ntThrMonStatus)
		return PsRemoveCreateThreadNotifyRoutine(ThreadCreateMon);
	//else
		//return STATUS_INVALID_PARAMETER;
}

//----------------------------------------------------------

NTSTATUS GetRegistryObjectCompleteName(
	IN PUNICODE_STRING pRegistryPath,
	IN PUNICODE_STRING pPartialRegistryPath,
	IN PVOID pRegistryObject
) {
	if (pRegistryObject && pRegistryPath)
	{
		if (pPartialRegistryPath)
		{
			if ((((pPartialRegistryPath->Buffer[0] == '\\') || (pPartialRegistryPath->Buffer[0] == '%')) ||
				((pPartialRegistryPath->Buffer[0] == 'T') &&
					(pPartialRegistryPath->Buffer[1] == 'R') &&
					(pPartialRegistryPath->Buffer[2] == 'Y') &&
					(pPartialRegistryPath->Buffer[3] == '\\'))))
				//if (pRegistryPath->MaximumLength >= pPartialRegistryPath->Length)
			{
				/*
				RtlZeroMemory(pRegistryPath->Buffer, pRegistryPath->MaximumLength);
				memcpy(pRegistryPath->Buffer, pPartialRegistryPath->Buffer, pPartialRegistryPath->Length);
				pRegistryPath->Length = pPartialRegistryPath->Length;
				*/
				pRegistryPath->Buffer = pPartialRegistryPath->Buffer;
				pRegistryPath->MaximumLength = pPartialRegistryPath->MaximumLength;
				pRegistryPath->Length = pPartialRegistryPath->Length;
				return STATUS_SUCCESS;
			}
			//else
			//	return STATUS_INFO_LENGTH_MISMATCH;
		//	else
		//		return STATUS_INFO_LENGTH_MISMATCH;
		}
		//else
		//{
		ULONG ReturnedLength = 0;
		if (ObQueryNameString(pRegistryObject, NULL, 0, &ReturnedLength) == STATUS_INFO_LENGTH_MISMATCH)
		{
			PUNICODE_STRING pObjectName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, ReturnedLength, 'NC');
			if (pObjectName)
			{
				NTSTATUS ntStatus = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, ReturnedLength, &ReturnedLength);
				if (NT_SUCCESS(ntStatus))
				{
					if (pRegistryPath->MaximumLength >= pObjectName->Length)
					{
						RtlZeroMemory(pRegistryPath->Buffer, pRegistryPath->MaximumLength);
						memcpy(pRegistryPath->Buffer, pObjectName->Buffer, pObjectName->Length);
						pRegistryPath->Length = pObjectName->Length;
					}
					else
						ntStatus = STATUS_INFO_LENGTH_MISMATCH;
				}

				ExFreePoolWithTag(pObjectName, 'NC');
				return ntStatus;
			}
			else
				return STATUS_MEMORY_NOT_ALLOCATED;
		}
		else
			return STATUS_UNSUCCESSFUL;
		//}
	}
	else
		return STATUS_INVALID_PARAMETER;
}

NTSTATUS RegistryMon
(
	IN PVOID CallbackContext,
	IN PVOID RegNotifyClasee,
	IN PVOID RegInformation
) {
	NTSTATUS CallbackStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		UNICODE_STRING RegistryPath = { 0 };

	if (!RegNotifyClasee || !RegInformation)
		return STATUS_INVALID_PARAMETER;

	static PWCHAR Buffer[MAX_PATH + 1] = { 0 };
	RegistryPath.Length = 0;
	RegistryPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
	RegistryPath.Buffer = (PWCH)Buffer;

	HANDLE PID = PsGetCurrentProcessId();
	PEPROCESS pEProc = PsGetCurrentProcess();
	PUNICODE_STRING puniProcImageName = NULL;
	CallbackStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
	if (!NT_SUCCESS(CallbackStatus))
	{
		PrintErr("[REG_MON] SeLocateProcessImageName Fail! Errorcode:%X\n", CallbackStatus);
		return STATUS_UNSUCCESSFUL;
	}

	switch ((REG_NOTIFY_CLASS)(UINT64)RegNotifyClasee)
	{
		case RegNtPreCreateKeyEx:	//出现两次是因为一次是OpenKey，一次是createKey
		{
			if (NT_SUCCESS(GetRegistryObjectCompleteName(&RegistryPath, ((PREG_CREATE_KEY_INFORMATION)RegInformation)->CompleteName, ((PREG_CREATE_KEY_INFORMATION)RegInformation)->RootObject)))
			{
				PrintIfm("[REG_MON] [RegNtPreCreateKeyEx] ProcPath:%wZ ,KeyPath:%wZ ,KeyName:%wZ ,ProcID:%I64u\n", puniProcImageName, RegistryPath, ((PREG_CREATE_KEY_INFORMATION)RegInformation)->CompleteName, (UINT64)PID);
				CallbackStatus = STATUS_SUCCESS;
			}
			else
				PrintErr("[REG_MON] GetRegistryObjectCompleteName Fail!");

			break;
		}
		case RegNtPreDeleteKey:
		{
			if (NT_SUCCESS(GetRegistryObjectCompleteName(&RegistryPath, NULL, ((PREG_DELETE_KEY_INFORMATION)RegInformation)->Object)))
			{
				PrintIfm("[REG_MON] [RegNtPreDeleteKey] ProcPath:%wZ ,KeyPath:%wZ ,ProcID:%I64u\n", puniProcImageName, RegistryPath, (UINT64)PID);
				CallbackStatus = STATUS_SUCCESS;
			}
			else
				PrintErr("[REG_MON] GetRegistryObjectCompleteName Fail!");

			break;
		}
		case RegNtPreSetValueKey:
		{
			if (NT_SUCCESS(GetRegistryObjectCompleteName(&RegistryPath, ((PREG_SET_VALUE_KEY_INFORMATION)RegInformation)->ValueName, ((PREG_SET_VALUE_KEY_INFORMATION)RegInformation)->Object)))
			{
				PrintIfm("[REG_MON] [RegNtPreSetValueKey] ProcPath:%wZ ,KeyPath:%wZ ,ValName:%wZ ,ProcID:%I64u\n", puniProcImageName, RegistryPath, ((PREG_SET_VALUE_KEY_INFORMATION)RegInformation)->ValueName, (UINT64)PID);
				CallbackStatus = STATUS_SUCCESS;
			}
			else
				PrintErr("[REG_MON] GetRegistryObjectCompleteName Fail!");

			break;
		}
		case RegNtPreDeleteValueKey:
		{
			if (NT_SUCCESS(GetRegistryObjectCompleteName(&RegistryPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)RegInformation)->ValueName, ((PREG_DELETE_VALUE_KEY_INFORMATION)RegInformation)->Object)))
			{
				PrintIfm("[REG_MON] [RegNtPreDeleteValueKey] ProcPath:%wZ ,KeyPath:%wZ ,ValName:%wZ ,ProcID:%I64u\n", puniProcImageName, RegistryPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)RegInformation)->ValueName, (UINT64)PID);
				CallbackStatus = STATUS_SUCCESS;
			}
			else
				PrintErr("[REG_MON] GetRegistryObjectCompleteName Fail!");

			break;
		}
		case RegNtPreRenameKey:
		{
			if (NT_SUCCESS(GetRegistryObjectCompleteName(&RegistryPath, ((PREG_RENAME_KEY_INFORMATION)RegInformation)->NewName, ((PREG_RENAME_KEY_INFORMATION)RegInformation)->Object)))
			{
				PrintIfm("[REG_MON] [RegNtPreRenameKey] ProcPath:%wZ ,KeyPath:%wZ ,NewName:%wZ ,ProcID:%I64u\n", puniProcImageName, RegistryPath, ((PREG_RENAME_KEY_INFORMATION)RegInformation)->NewName, (UINT64)PID);
				CallbackStatus = STATUS_SUCCESS;
			}
			else
				PrintErr("[REG_MON] GetRegistryObjectCompleteName Fail!");

			break;
		}
		//注册表编辑器 里的“重命名键值”是没有直接函数的，是先SetValueKey再DeleteValueKey
		default:
			return STATUS_SUCCESS;
	}

	if (g_ProtSelfReg_Switch)
	{
		RegistryPath.Buffer[MAX_PATH] = 0;
		if (wcsstr(RegistryPath.Buffer, L"WinKiller_Driver"))
			CallbackStatus = STATUS_ACCESS_DENIED;
		if (wcsstr(RegistryPath.Buffer, L"SuperDriver"))
			CallbackStatus = STATUS_ACCESS_DENIED;
	}

	TRY_END(CallbackStatus);
}

NTSTATUS Mon_CreateRegMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
		return CmRegisterCallback(RegistryMon, NULL, &g_RegCallbackHandle);
	else
		//if (g_ntRegMonStatus)
		return CmRegisterCallback(RegistryMon, NULL, &g_RegCallbackHandle);
	//else
		//return STATUS_INVALID_PARAMETER;
}

//---------------------------------------------------------------------------

VOID EnableObType(
	IN POBJECT_TYPE ObjectType
)
{
	POBJECT_TYPE_TEMP ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
	ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
	return;
}

//-------------------------------------------------------------------------------

OB_PREOP_CALLBACK_STATUS FileMon(
	IN PVOID RegistrationContext,
	IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	TRY_START

		UNICODE_STRING uniDosName = { 0 };
	PUNICODE_STRING uniFilePath = NULL;
	PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
	HANDLE CurrentProcessID = PsGetCurrentProcessId();

	if (OperationInformation->ObjectType != *IoFileObjectType)
		return OB_PREOP_SUCCESS;

	//过滤无效指针
	if (FileObject->FileName.Buffer == NULL ||
		!MmIsAddressValid(FileObject->FileName.Buffer) ||
		FileObject->DeviceObject == NULL ||
		!MmIsAddressValid(FileObject->DeviceObject))
		return OB_PREOP_SUCCESS;

	uniFilePath = GetFilePathByFileObject(FileObject);
	if (uniFilePath->Buffer == NULL || uniFilePath->Length == 0)
		return OB_PREOP_SUCCESS;

	PEPROCESS pEProc = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(CurrentProcessID, &pEProc);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON_EX] PsLookupProcessByProcessId Fail! Errorcode:%X\n", ntStatus);
		return OB_PREOP_SUCCESS;
	}

	PUNICODE_STRING puniProcImageName = NULL;
	ntStatus = SeLocateProcessImageName(pEProc, &puniProcImageName);
	if (!NT_SUCCESS(ntStatus))
	{
		PrintErr("[PROC_MON] SeLocateProcessImageName Fail! Errorcode:%X\n", ntStatus);
		return OB_PREOP_SUCCESS;
	}
	ObDereferenceObject(pEProc);

	RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName);
	PrintIfm("[FILE_CALLBACK] PID:%I64u ,DosName:%wZ ,FilePath:%wZ\n", (UINT64)CurrentProcessID, uniDosName, uniFilePath);

	if (g_ProtAllFile_Switch || List_CheckNoWildcard(&g_ProtFileList, (LPVOID)uniFilePath->Buffer, uniFilePath->Length))
	{
		if ((OperationInformation->Operation & OB_OPERATION_HANDLE_CREATE) == OB_OPERATION_HANDLE_CREATE || (OperationInformation->Operation & OB_OPERATION_HANDLE_DUPLICATE) == OB_OPERATION_HANDLE_DUPLICATE)
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
	}

	TRY_END(OB_PREOP_SUCCESS)
}

NTSTATUS Mon_CreateFileMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
	{
		OB_CALLBACK_REGISTRATION CallBackReg;
		OB_OPERATION_REGISTRATION OperationReg;

		EnableObType(*IoFileObjectType);      //开启文件对象回调
		memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
		CallBackReg.Version = ObGetFilterVersion();
		CallBackReg.OperationRegistrationCount = 1;
		CallBackReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");
		memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量

		OperationReg.ObjectType = IoFileObjectType;
		OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

		OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&FileMon); //在这里注册一个回调函数指针
		CallBackReg.OperationRegistration = &OperationReg; //注意这一条语句   将结构体信息放入大结构体
		return ObRegisterCallbacks(&CallBackReg, &g_FileCallbackHandle);
	}
	else
	{
		ObUnRegisterCallbacks(g_FileCallbackHandle);
		return STATUS_SUCCESS;
	}
}

//---------------------------------------------------------------------------------------

OB_PREOP_CALLBACK_STATUS ProcKillMon(
	IN PVOID RegistrationContext,
	IN POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	TRY_START

		HANDLE PID = PsGetProcessId((PEPROCESS)pOperationInformation->Object);

	PrintIfm("[+] [PROCKILL_CALLBACK] PID:%I64u\n", (UINT64)PID);

	if (List_CheckNoWildcard(&g_ProtProcList, (LPVOID)&PID, sizeof(PID)))
		if (pOperationInformation->Operation & OB_OPERATION_HANDLE_CREATE || pOperationInformation->Operation & OB_OPERATION_HANDLE_DUPLICATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE || (pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION || (pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ || (pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		}

	TRY_END(OB_PREOP_SUCCESS)
}

NTSTATUS Mon_CreateProcKillMon(
	IN BOOLEAN bCreate
) {
	if (bCreate)
	{
		OB_CALLBACK_REGISTRATION obReg;
		OB_OPERATION_REGISTRATION opReg;

		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321000");

		memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

		opReg.ObjectType = PsProcessType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&ProcKillMon);  //注册回调函数指针

		obReg.OperationRegistration = &opReg; //注意这一条语句
		return ObRegisterCallbacks(&obReg, &g_ProcKillCallbackHandle); //注册回调函数
	}
	else
	{
		ObUnRegisterCallbacks(g_ProcKillCallbackHandle);
		return STATUS_SUCCESS;
	}
}