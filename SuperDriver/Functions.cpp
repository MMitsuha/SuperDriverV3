#include "Functions.h"

NTSTATUS GetDriverObjectByName(
	IN PDRIVER_OBJECT* DriverObject,
	IN PWCHAR DriverName
)
{
	UNICODE_STRING uniDriverName = { 0 };
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&uniDriverName, DriverName);
	ntStatus = ObReferenceObjectByName(&uniDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)DriverObject);
	if (!NT_SUCCESS(ntStatus))
		*DriverObject = NULL;

	return ntStatus;
}

/*********************************************************************************************/

PUCHAR _PsGetProcessNameByProcessID(
	IN HANDLE PID
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	Status = PsLookupProcessByProcessId(PID, &pEProcess);

	if (!NT_SUCCESS(Status))
		return NULL;

	ObDereferenceObject(pEProcess);
	return PsGetProcessImageFileName(pEProcess);
}

PUNICODE_STRING GetFilePathByFileObject(
	IN PFILE_OBJECT FileObject
)
{
	POBJECT_NAME_INFORMATION ObjetNameInfor;
	if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &ObjetNameInfor)))
		return &(ObjetNameInfor->Name);

	return NULL;
}

/*********************************************************************************************/

ULONG GetActiveProcessLinksOffset(
	VOID
) {
	ULONG ulOffset = 0;
	RTL_OSVERSIONINFOW osInfo = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	// 获取系统版本信息
	status = RtlGetVersion(&osInfo);
	if (!NT_SUCCESS(status))
	{
		PrintErr("[GetActiveProcessLinksOffset] RtlGetVersion Fail... Errorcode:%X\n", status);
		return ulOffset;
	}
	// 判断系统版本
	switch (osInfo.dwMajorVersion)
	{
		case 6:
		{
			switch (osInfo.dwMinorVersion)
			{
				case 1:
				{
					// Win7
#ifdef _WIN64
			// 64 Bits
					ulOffset = 0x188;
#else
			// 32 Bits
					ulOffset = 0x0B8;
#endif
					break;
				}
				case 2:
				{
					// Win8
#ifdef _WIN64
			// 64 Bits
#else
			// 32 Bits
#endif
					break;
				}
				case 3:
				{
					// Win8.1
#ifdef _WIN64
			// 64 Bits
					ulOffset = 0x2E8;
#else
			// 32 Bits
					ulOffset = 0x0B8;
#endif
					break;
				}
				default:
					break;
			}
			break;
		}
		case 10:
		{
			// Win10
#ifdef _WIN64
		// 64 Bits
			ulOffset = 0x2F0;
#else
		// 32 Bits
			ulOffset = 0x0B8;
#endif
			break;
		}
		default:
			break;
	}
	return ulOffset;
}

BOOLEAN _ZwHideProcess(
	IN HANDLE PID
)
{
	BOOLEAN Found = FALSE;
	PEPROCESS pFirstEProcess = NULL, pEProcess = NULL;
	ULONG ulOffset = 0;
	HANDLE hProcessID = NULL;
	// 根据不同系统, 获取相应偏移大小
	ulOffset = GetActiveProcessLinksOffset();
	if (0 == ulOffset)
	{
		PrintErr("[_ZwHideProcess] GetActiveProcessLinksOffset Fail!\n");
		return FALSE;
	}
	// 获取当前进程结构对象
	pFirstEProcess = PsGetCurrentProcess();
	pEProcess = pFirstEProcess;
	// 开始遍历枚举进程
	do
	{
		// 从 EPROCESS 获取进程 PID
		hProcessID = PsGetProcessId(pEProcess);
		// 隐藏指定进程
		if (PID == hProcessID)
		{
			// 摘链
			RemoveEntryList((PLIST_ENTRY)((PUCHAR)pEProcess + ulOffset));
			Found = TRUE;
			break;
		}
		// 根据偏移计算下一个进程的 EPROCESS
		pEProcess = (PEPROCESS)((PUCHAR)(((PLIST_ENTRY)((PUCHAR)pEProcess + ulOffset))->Flink) - ulOffset);
	} while (pFirstEProcess != pEProcess);
	return Found;
}

NTSTATUS _ZwOpenProcess(
	IN HANDLE PID,
	OUT PHANDLE hProcess
)
{
	OBJECT_ATTRIBUTES objOA = { 0 };
	CLIENT_ID objCID = { 0 };

	objCID.UniqueProcess = PID;		//进程PID
	objOA.Length = sizeof(objOA);
	return ZwOpenProcess(hProcess, PROCESS_ALL_ACCESS, &objOA, &objCID);//打开进程
}

NTSTATUS _ZwTerminateProcess(
	IN HANDLE hProcess
)
{
	OBJECT_ATTRIBUTES objOA = { 0 };
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	HANDLE hJob = NULL;

	objOA.Length = sizeof(OBJECT_ATTRIBUTES);
	ntStatus = ZwCreateJobObject(&hJob, 0, &objOA);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ZwAssignProcessToJobObject(hJob, (HANDLE)hProcess);
		if (NT_SUCCESS(ntStatus))
			ZwTerminateJobObject(hJob, 0);
		ZwClose(hJob);
	}
	return ntStatus;
}

NTSTATUS _ZwKillProcess(
	IN HANDLE PID
)
{
	if (PID)
	{
		HANDLE hProcess = NULL;
		CLIENT_ID ClientID = { 0 };
		OBJECT_ATTRIBUTES objOA = { 0 };
		//填充 CID
		ClientID.UniqueProcess = PID;
		ClientID.UniqueThread = 0;
		//填充 OA
		objOA.Length = sizeof(objOA);
		objOA.RootDirectory = 0;
		objOA.ObjectName = 0;
		objOA.Attributes = 0;
		objOA.SecurityDescriptor = 0;
		objOA.SecurityQualityOfService = 0;
		//打开进程，如果句柄有效，则结束进程
		ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objOA, &ClientID);
		if (hProcess)
		{
			NTSTATUS Status = ZwTerminateProcess(hProcess, 0);
			ZwClose(hProcess);
			return Status;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

VOID _ZwZEROKillProcessThread(
	IN LPVOID PID
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		PEPROCESS Eprocess = NULL;
	ntStatus = PsLookupProcessByProcessId(PID, &Eprocess);
	if (NT_SUCCESS(ntStatus))
	{
		PrintSuc("[_ZwZEROKillProcessThread] LookUp Success!\n");
		KAPC_STATE pKs = { 0 };
		KeStackAttachProcess(Eprocess, &pKs);		//Attach进程虚拟空间
		for (UINT64 i = PAGE_SIZE; i <= 0x7FFFFFFF; i += PAGE_SIZE)
		{
			if (MmIsAddressValid((PVOID)i))
			{
				__try
				{
					ProbeForWrite((PVOID)i, PAGE_SIZE, PAGE_SIZE);
					memset((PVOID)i, 0x00, PAGE_SIZE);
				}
				__except (1)
				{
					continue;
				}
			}
			else
				if (i > 0x03FFFFFF)  //填这么多足够破坏进程数据了
					break;
		}
		KeUnstackDetachProcess(&pKs);

		//ntStatus = _ZwKillProcess(PID);
		if (NT_SUCCESS(ntStatus))
			PrintSuc("[_ZwZEROKillProcessThread] Finnal Kill Success!\n");
		else
			PrintErr("[_ZwZEROKillProcessThread] Finnal Kill Fali! Errorcode:%X\n", ntStatus);

		ObDereferenceObject(Eprocess);
	}
	else
		PrintErr("[_ZwZEROKillProcessThread] LookUp Fail! Errorcode:%X\n", ntStatus);
	PsTerminateSystemThread(ntStatus);

	TRY_END_NOSTATUS
}

VOID _ZwCCKillProcessThread(
	IN LPVOID PID
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		PEPROCESS Eprocess = NULL;
	ntStatus = PsLookupProcessByProcessId(PID, &Eprocess);
	if (NT_SUCCESS(ntStatus))
	{
		PrintSuc("[_ZwCCKillProcessThread] LookUp Success!\n");
		KAPC_STATE pKs = { 0 };
		KeStackAttachProcess(Eprocess, &pKs);		//Attach进程虚拟空间
		for (UINT64 i = PAGE_SIZE; i <= 0x7FFFFFFF; i += PAGE_SIZE)
		{
			if (MmIsAddressValid((PVOID)i))
			{
				__try
				{
					ProbeForWrite((PVOID)i, PAGE_SIZE, PAGE_SIZE);
					memset((PVOID)i, 0x00, PAGE_SIZE);
				}
				__except (1)
				{
					continue;
				}
			}
			else
				if (i > 0x03FFFFFF)  //填这么多足够破坏进程数据了
					break;
		}
		KeUnstackDetachProcess(&pKs);

		//ntStatus = _ZwKillProcess(PID);
		if (NT_SUCCESS(ntStatus))
			PrintSuc("[_ZwCCKillProcessThread] Finnal Kill Success!\n");
		else
			PrintErr("[_ZwCCKillProcessThread] Finnal Kill Fali! Errorcode:%X\n", ntStatus);

		ObDereferenceObject(Eprocess);
	}
	else
		PrintErr("[_ZwCCKillProcessThread] LookUp Fail! Errorcode:%X\n", ntStatus);
	PsTerminateSystemThread(ntStatus);

	TRY_END_NOSTATUS
}

NTSTATUS _ZwSuperKillProcess(
	IN BOOLEAN IsCC,
	IN HANDLE PID
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hThread = NULL;
	if (IsCC)
		ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, _ZwZEROKillProcessThread, PID);
	else
		ntStatus = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, _ZwCCKillProcessThread, PID);
	if (NT_SUCCESS(ntStatus))
		ZwClose(hThread);
	return ntStatus;
}

/*********************************************************************************************/
/*
NTSTATUS _ZwKillThread(
	IN HANDLE TID
)
{
	if (TID)
	{
		HANDLE hThread = NULL;
		CLIENT_ID ClientId = { 0 };
		OBJECT_ATTRIBUTES objOA = { 0 };
		//填充 CID
		ClientId.UniqueProcess = 0;
		ClientId.UniqueThread = TID;
		//填充 OA
		objOA.Length = sizeof(objOA);
		objOA.RootDirectory = 0;
		objOA.ObjectName = 0;
		objOA.Attributes = 0;
		objOA.SecurityDescriptor = 0;
		objOA.SecurityQualityOfService = 0;
		//打开进程，如果句柄有效，则结束进程
		ZwOpenProcess(&hThread, PROCESS_ALL_ACCESS, &objOA, &ClientId);
		if (hThread)
		{
			NTSTATUS Status = ZwTerminateThread(hThread, 0);
			ZwClose(hThread);
			return Status;
		}
	}
	return STATUS_UNSUCCESSFUL;
}
*/
/*********************************************************************************************/

NTSTATUS _ZwSuperDeleteFile(
	IN PWCHAR wstrDeletePathName
)
{
	//
	//思路:
	//1.初始化文件路径
	//2.使用读写方式打开文件. 以共享模式打开.
	//3.如果是拒绝,则以另一种方式打开文件.并且设置这个文件的信息.
	//4.设置成功之后就可以删除了.
	//
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		UNICODE_STRING ustrDeletePathName = { 0 };
	RtlInitUnicodeString(&ustrDeletePathName, wstrDeletePathName);
	OBJECT_ATTRIBUTES objAttri = { 0 };
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatus = { 0 };
	FILE_DISPOSITION_INFORMATION IBdelPostion = { 0 }; //通过ZwSetInformationFile删除.需要这个结构体

	InitializeObjectAttributes(&objAttri,
		&ustrDeletePathName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	ntStatus = ZwCreateFile(&hFile,
		DELETE | FILE_WRITE_DATA | SYNCHRONIZE, //注意权限,以删除权限.写权限.
		&objAttri,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,                //文件的属性是默认
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,//文件的共享模式 删除 读写
		FILE_OPEN,  //文件的打开方式是 打开.如果不存在则返回失败.
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, //文件的应用选项,如果是FILE_DELETE_ON_CLOSE则使用ZwClose关闭文件句柄的时候删除这个文件
		NULL,
		0
	);
	if (!NT_SUCCESS(ntStatus))
	{
		//如果不成功,判断文件是否拒绝访问.是的话我们就设置为可以访问.并且进行删除.
		if (STATUS_ACCESS_DENIED == ntStatus)
		{
			ntStatus = ZwCreateFile(&hFile,
				SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,//删除权限失败就以读写模式
				&objAttri,
				&ioStatus,
				NULL,
				FILE_ATTRIBUTE_NORMAL,                                  //文件的属性为默认
				FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,//文件的共享属性为 读写删除
				FILE_OPEN,                                            //文件的打开方式为 打开,不存在则失败
				FILE_SYNCHRONOUS_IO_NONALERT,                         //文件的应用选项.
				NULL,
				0
			);
			//如果打开成功了.则设置这个文件的信息
			if (NT_SUCCESS(ntStatus))
			{
				FILE_BASIC_INFORMATION  IBFileBasic = { 0 };
				//使用ZwQueryInformationfile遍历文件的信息.这里遍历的是文件的基本信息

				ntStatus = ZwQueryInformationFile(
					hFile,
					&ioStatus,
					&IBFileBasic,
					sizeof(IBFileBasic),
					FileBasicInformation
				);
				//遍历失败.输出打印信息
				if (!NT_SUCCESS(ntStatus))
					/*KdPrint(("NtDeleteFile()! ZwQueryInformationFile ,FileName:%wZ", uDeletePathName));*/
					return ntStatus;

				//设置文件的基本信息
				IBFileBasic.FileAttributes = FILE_ATTRIBUTE_NORMAL; //设置属性为默认属性

				ntStatus = ZwSetInformationFile(
					hFile,
					&ioStatus,
					&IBFileBasic,
					sizeof(IBFileBasic),
					FileBasicInformation); //将我的FileBasic基本属性设置到这个文件中

				ZwClose(hFile);		//如果成功关闭文件句柄.
				if (!NT_SUCCESS(ntStatus))
					/*KdPrint(("NtDeleteFile()! ZwSetInformationFile"));*/
					return ntStatus;

				//重新打开这个设置信息后的文件.

				ntStatus = ZwCreateFile(&hFile,
					SYNCHRONIZE | FILE_WRITE_DATA | DELETE,
					&objAttri,
					&ioStatus,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
					NULL,
					0);
			}
			else
				/*KdPrint(("NtDeleteFile()! ZwCreateFile"));*/
				return ntStatus;
		}
	}

	//进行强制删除文件 通过 ZwSetInformationFile

	IBdelPostion.DeleteFile = TRUE; //此标志设置为TRUE即可删除
	ntStatus = ZwSetInformationFile(hFile, &ioStatus, &IBdelPostion, sizeof(IBdelPostion), FileDispositionInformation);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hFile);
		/*KdPrint(("NtDeleteFile()! ZwSetInformationFile"));*/
		return ntStatus;
	}
	ZwClose(hFile);

	TRY_END(ntStatus);
}

NTSTATUS _ZwDeleteFile(
	IN PWCHAR wstrFileName
)
{
	UNICODE_STRING ustrFileName = { 0 };
	RtlInitUnicodeString(&ustrFileName, wstrFileName);
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes,
		&ustrFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	return ZwDeleteFile(&ObjectAttributes);
}

NTSTATUS _ZwCopyFile(
	IN PCWSTR wstrWriteFilePath,
	IN PCWSTR wstrReadFilePath
)
{
	HANDLE hReadFileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributesRead = { 0 };
	UNICODE_STRING ustrReadFilePath = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	LPVOID pBuffer = NULL;
	FILE_STANDARD_INFORMATION FileInformation = { 0 };
	NTSTATUS ntStatus = STATUS_SUCCESS;

	LARGE_INTEGER ByteOffset = { 0 };

	ByteOffset.QuadPart = 0;
	RtlInitUnicodeString(&ustrReadFilePath, wstrReadFilePath);

	InitializeObjectAttributes(&ObjectAttributesRead, &ustrReadFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwCreateFile(&hReadFileHandle, GENERIC_READ, &ObjectAttributesRead, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ZwQueryInformationFile(hReadFileHandle, &IoStatusBlock, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(ntStatus))
		{
			pBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)FileInformation.EndOfFile.QuadPart, 'FC');
			if (pBuffer)
				if (MmIsAddressValid(pBuffer))
				{
					HANDLE hWriteFileHandle = NULL;
					OBJECT_ATTRIBUTES ObjectAttributesWrite = { 0 };
					UNICODE_STRING ustrWriteFilePath = { 0 };
					RtlInitUnicodeString(&ustrWriteFilePath, wstrWriteFilePath);
					InitializeObjectAttributes(&ObjectAttributesWrite, &ustrWriteFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
					ntStatus = ZwCreateFile(&hWriteFileHandle, GENERIC_WRITE, &ObjectAttributesWrite, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
					if (NT_SUCCESS(ntStatus))
					{
						ntStatus = ZwReadFile(hReadFileHandle, NULL, NULL, NULL, &IoStatusBlock, pBuffer, (ULONG)FileInformation.EndOfFile.QuadPart, &ByteOffset, NULL);		//读取数据
						if (NT_SUCCESS(ntStatus))
						{
							ByteOffset.QuadPart = 0;
							ntStatus = ZwWriteFile(hWriteFileHandle, NULL, NULL, NULL, &IoStatusBlock, pBuffer, (ULONG)FileInformation.EndOfFile.QuadPart, &ByteOffset, NULL);
						}
						ZwClose(hWriteFileHandle);
					}
					ExFreePoolWithTag(pBuffer, 'FC');
				}
		}
		ZwClose(hReadFileHandle);
	}

	return ntStatus;
}

/*********************************************************************************************/

NTSTATUS AddSelfToSafeMode(
	IN CONST UNICODE_STRING ustrRegistryPath
)
{
	NTSTATUS ntStatus;
	HANDLE hDriverKey = NULL;
	OBJECT_ATTRIBUTES objDriverKeyObject;
	InitializeObjectAttributes(&objDriverKeyObject, (PUNICODE_STRING)&ustrRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwOpenKey(&hDriverKey, KEY_ALL_ACCESS, &objDriverKeyObject);
	if (NT_SUCCESS(ntStatus))
	{
		UNICODE_STRING ustrValueName = RTL_CONSTANT_STRING(L"ImagePath");
		ULONG Length = 0;
		ZwQueryValueKey(hDriverKey, &ustrValueName, KeyValuePartialInformation, NULL, 0, &Length);
		PKEY_VALUE_PARTIAL_INFORMATION KeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, 'GERS');
		if (KeyInfo)
			if (MmIsAddressValid(KeyInfo))
			{
				ntStatus = ZwQueryValueKey(hDriverKey, &ustrValueName, KeyValuePartialInformation, KeyInfo, Length, &Length);
				if (NT_SUCCESS(ntStatus))
				{
					ntStatus = ZwSetValueKey(hDriverKey, &ustrValueName, 0, REG_SZ, L"\\SystemRoot\\System32\\drivers\\SuperDriver.sys", sizeof(L"\\SystemRoot\\System32\\drivers\\SuperDriver.sys"));
					if (NT_SUCCESS(ntStatus))
					{
						DWORD Start = SERVICE_BOOT_START;
						UNICODE_STRING ustrStartName = RTL_CONSTANT_STRING(L"Start");
						ntStatus = ZwSetValueKey(hDriverKey, &ustrStartName, 0, REG_DWORD, &Start, sizeof(Start));

						if (NT_SUCCESS(ntStatus))
						{
							_ZwCopyFile(L"\\SystemRoot\\System32\\drivers\\SuperDriver.sys", (PCWSTR)KeyInfo->Data);
							UNICODE_STRING ustrSafeBoot = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\SuperDriver.sys");
							OBJECT_ATTRIBUTES objSafeBoot = { 0 };
							HANDLE hSafeBoot = NULL;
							ULONG Disposition = 0;
							InitializeObjectAttributes(&objSafeBoot, &ustrSafeBoot, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
							ntStatus = ZwCreateKey(&hSafeBoot, KEY_ALL_ACCESS, &objSafeBoot, 0, &ustrSafeBoot, REG_OPTION_NON_VOLATILE, &Disposition);
							if (NT_SUCCESS(ntStatus))
							{
								UNICODE_STRING Empty = { 0 };
								ntStatus = ZwSetValueKey(hSafeBoot, &Empty, 0, REG_SZ, L"Driver", sizeof(L"Driver"));
								if (NT_SUCCESS(ntStatus))
								{
									UNICODE_STRING _ustrSafeBoot = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\SuperDriver.sys");
									OBJECT_ATTRIBUTES _objSafeBoot = { 0 };
									HANDLE _hSafeBoot = NULL;
									ULONG _Disposition = 0;
									InitializeObjectAttributes(&_objSafeBoot, &_ustrSafeBoot, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
									ntStatus = ZwCreateKey(&_hSafeBoot, KEY_ALL_ACCESS, &_objSafeBoot, 0, &_ustrSafeBoot, REG_OPTION_NON_VOLATILE, &_Disposition);
									if (NT_SUCCESS(ntStatus))
									{
										ntStatus = ZwSetValueKey(_hSafeBoot, &Empty, 0, REG_SZ, L"Driver", sizeof(L"Driver"));
										ZwClose(_hSafeBoot);
									}
								}
								ZwClose(hSafeBoot);
							}
						}
					}
				}
				ExFreePoolWithTag(KeyInfo, 'GERS');
			}
			else
				ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
		ZwClose(hDriverKey);
	}
	return ntStatus;
}

NTSTATUS DelSelfFromSafeMode(
	IN CONST UNICODE_STRING ustrRegistryPath
) {
	NTSTATUS ntStatus;
	HANDLE hDriverKey = NULL;
	OBJECT_ATTRIBUTES objDriverKeyObject;
	InitializeObjectAttributes(&objDriverKeyObject, (PUNICODE_STRING)&ustrRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwOpenKey(&hDriverKey, KEY_ALL_ACCESS, &objDriverKeyObject);
	if (NT_SUCCESS(ntStatus))
	{
		DWORD Start = SERVICE_SYSTEM_START;
		UNICODE_STRING ustrStartName = RTL_CONSTANT_STRING(L"Start");
		ntStatus = ZwSetValueKey(hDriverKey, &ustrStartName, 0, REG_DWORD, &Start, sizeof(Start));
		ZwClose(hDriverKey);
	}
	return ntStatus;
}

/*********************************************************************************************/

PWCHAR PCHARToPWCHAR(
	IN CONST PCHAR Sur
)
{
	ANSI_STRING ASSur = { 0 };
	RtlInitAnsiString(&ASSur, Sur);
	UNICODE_STRING USDst = { 0 };
	RtlAnsiStringToUnicodeString(&USDst, &ASSur, TRUE);
	return USDst.Buffer;
}

PCHAR PWCHARToPCHAR(
	IN CONST PWCHAR Sur
)
{
	UNICODE_STRING USSur = { 0 };
	RtlInitUnicodeString(&USSur, Sur);
	ANSI_STRING ASDst = { 0 };
	RtlUnicodeStringToAnsiString(&ASDst, &USSur, TRUE);
	return ASDst.Buffer;
}

/*********************************************************************************************/

VOID RemoveWP(
	OUT PKIRQL pirQl
)
{
	// (PASSIVE_LEVEL)提升 IRQL 等级为DISPATCH_LEVEL，并返回旧的 IRQL
	// 需要一个高的IRQL才能修改
	*pirQl = KeRaiseIrqlToDpcLevel();
	ULONG_PTR cr0 = __readcr0(); // 内联函数：读取Cr0寄存器的值, 相当于: mov eax,  cr0;

	// 将第16位（WP位）清0，消除写保护
	cr0 &= ~0x10000; // ~ 按位取反
	_disable(); // 清除中断标记, 相当于 cli 指令，修改 IF标志位
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax
}
// 复原Cr0寄存器
VOID RecoveryWP(
	IN PKIRQL pirQl
)
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000; // WP复原为1
	_disable(); // 清除中断标记, 相当于 cli 指令，清空 IF标志位
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax

	// 恢复IRQL等级
	KeLowerIrql(*pirQl);
}

/*********************************************************************************************/

NTSTATUS GetDiskMiniport(
	IN OUT PDEVICE_OBJECT* DeviceObject,
	IN PUNICODE_STRING uniDeviceName
)
{
	PDEVICE_OBJECT LowerDevice = NULL;
	PFILE_OBJECT FileObject = NULL;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hDevice = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK StatusBlock = { 0 };

	InitializeObjectAttributes(&ObjectAttributes, uniDeviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntStatus = ZwOpenFile(&hDevice, GENERIC_READ | GENERIC_WRITE, &ObjectAttributes, &StatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ObReferenceObjectByHandle(hDevice, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
		if (NT_SUCCESS(ntStatus))
		{
			LowerDevice = IoGetLowerDeviceObject(FileObject->DeviceObject);
			if (MmIsAddressValid(LowerDevice) && LowerDevice)
				*DeviceObject = LowerDevice;
			else
				ntStatus = STATUS_NOT_FOUND;
		}
		ZwClose(hDevice);
	}

	return ntStatus;
}

/***************************************************************************************/

NTSTATUS Sleep(
	IN UINT64 MilliSecond
)
{
	LARGE_INTEGER Interval = { 0 };
	Interval.QuadPart = DELAY_ONE_MILLISECOND;
	Interval.QuadPart *= MilliSecond;
	return KeDelayExecutionThread(KernelMode, 0, &Interval);
}

/***************************************************************************************/

ULONG MessageBox(
	PWSTR MessageString,
	PWSTR MessageTitle,
	ULONG ShowOpt,
	ULONG ResponseOption,
	PNTSTATUS pntStatus OPTIONAL
)
{
	UNICODE_STRING Message = { 0 };
	UNICODE_STRING Title = { 0 };
	ULONG Response = 0;

	RtlInitUnicodeString(&Message, MessageString);
	RtlInitUnicodeString(&Title, MessageTitle);

	ULONG_PTR Parameters[4] = {
	(ULONG_PTR)&Message, //内容
	(ULONG_PTR)&Title, //这是传说中的窗体标题...
	ShowOpt,
	0
	};

	if (pntStatus)
		*pntStatus = ExRaiseHardError(STATUS_SERVICE_NOTIFICATION | 0x10000000, 3, 3, &Parameters, ResponseOption, &Response);
	else
		ExRaiseHardError(STATUS_SERVICE_NOTIFICATION | 0x10000000, 3, 3, &Parameters, ResponseOption, &Response);

	return Response;
}