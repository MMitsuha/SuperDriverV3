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
	// ��ȡϵͳ�汾��Ϣ
	status = RtlGetVersion(&osInfo);
	if (!NT_SUCCESS(status))
	{
		PrintErr("[GetActiveProcessLinksOffset] RtlGetVersion Fail... Errorcode:%X\n", status);
		return ulOffset;
	}
	// �ж�ϵͳ�汾
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
	// ���ݲ�ͬϵͳ, ��ȡ��Ӧƫ�ƴ�С
	ulOffset = GetActiveProcessLinksOffset();
	if (0 == ulOffset)
	{
		PrintErr("[_ZwHideProcess] GetActiveProcessLinksOffset Fail!\n");
		return FALSE;
	}
	// ��ȡ��ǰ���̽ṹ����
	pFirstEProcess = PsGetCurrentProcess();
	pEProcess = pFirstEProcess;
	// ��ʼ����ö�ٽ���
	do
	{
		// �� EPROCESS ��ȡ���� PID
		hProcessID = PsGetProcessId(pEProcess);
		// ����ָ������
		if (PID == hProcessID)
		{
			// ժ��
			RemoveEntryList((PLIST_ENTRY)((PUCHAR)pEProcess + ulOffset));
			Found = TRUE;
			break;
		}
		// ����ƫ�Ƽ�����һ�����̵� EPROCESS
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

	objCID.UniqueProcess = PID;		//����PID
	objOA.Length = sizeof(objOA);
	return ZwOpenProcess(hProcess, PROCESS_ALL_ACCESS, &objOA, &objCID);//�򿪽���
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
		//��� CID
		ClientID.UniqueProcess = PID;
		ClientID.UniqueThread = 0;
		//��� OA
		objOA.Length = sizeof(objOA);
		objOA.RootDirectory = 0;
		objOA.ObjectName = 0;
		objOA.Attributes = 0;
		objOA.SecurityDescriptor = 0;
		objOA.SecurityQualityOfService = 0;
		//�򿪽��̣���������Ч�����������
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
		KeStackAttachProcess(Eprocess, &pKs);		//Attach��������ռ�
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
				if (i > 0x03FFFFFF)  //����ô���㹻�ƻ�����������
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
		KeStackAttachProcess(Eprocess, &pKs);		//Attach��������ռ�
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
				if (i > 0x03FFFFFF)  //����ô���㹻�ƻ�����������
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
		//��� CID
		ClientId.UniqueProcess = 0;
		ClientId.UniqueThread = TID;
		//��� OA
		objOA.Length = sizeof(objOA);
		objOA.RootDirectory = 0;
		objOA.ObjectName = 0;
		objOA.Attributes = 0;
		objOA.SecurityDescriptor = 0;
		objOA.SecurityQualityOfService = 0;
		//�򿪽��̣���������Ч�����������
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
	//˼·:
	//1.��ʼ���ļ�·��
	//2.ʹ�ö�д��ʽ���ļ�. �Թ���ģʽ��.
	//3.����Ǿܾ�,������һ�ַ�ʽ���ļ�.������������ļ�����Ϣ.
	//4.���óɹ�֮��Ϳ���ɾ����.
	//
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	TRY_START

		UNICODE_STRING ustrDeletePathName = { 0 };
	RtlInitUnicodeString(&ustrDeletePathName, wstrDeletePathName);
	OBJECT_ATTRIBUTES objAttri = { 0 };
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatus = { 0 };
	FILE_DISPOSITION_INFORMATION IBdelPostion = { 0 }; //ͨ��ZwSetInformationFileɾ��.��Ҫ����ṹ��

	InitializeObjectAttributes(&objAttri,
		&ustrDeletePathName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	ntStatus = ZwCreateFile(&hFile,
		DELETE | FILE_WRITE_DATA | SYNCHRONIZE, //ע��Ȩ��,��ɾ��Ȩ��.дȨ��.
		&objAttri,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,                //�ļ���������Ĭ��
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,//�ļ��Ĺ���ģʽ ɾ�� ��д
		FILE_OPEN,  //�ļ��Ĵ򿪷�ʽ�� ��.����������򷵻�ʧ��.
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, //�ļ���Ӧ��ѡ��,�����FILE_DELETE_ON_CLOSE��ʹ��ZwClose�ر��ļ������ʱ��ɾ������ļ�
		NULL,
		0
	);
	if (!NT_SUCCESS(ntStatus))
	{
		//������ɹ�,�ж��ļ��Ƿ�ܾ�����.�ǵĻ����Ǿ�����Ϊ���Է���.���ҽ���ɾ��.
		if (STATUS_ACCESS_DENIED == ntStatus)
		{
			ntStatus = ZwCreateFile(&hFile,
				SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,//ɾ��Ȩ��ʧ�ܾ��Զ�дģʽ
				&objAttri,
				&ioStatus,
				NULL,
				FILE_ATTRIBUTE_NORMAL,                                  //�ļ�������ΪĬ��
				FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,//�ļ��Ĺ�������Ϊ ��дɾ��
				FILE_OPEN,                                            //�ļ��Ĵ򿪷�ʽΪ ��,��������ʧ��
				FILE_SYNCHRONOUS_IO_NONALERT,                         //�ļ���Ӧ��ѡ��.
				NULL,
				0
			);
			//����򿪳ɹ���.����������ļ�����Ϣ
			if (NT_SUCCESS(ntStatus))
			{
				FILE_BASIC_INFORMATION  IBFileBasic = { 0 };
				//ʹ��ZwQueryInformationfile�����ļ�����Ϣ.������������ļ��Ļ�����Ϣ

				ntStatus = ZwQueryInformationFile(
					hFile,
					&ioStatus,
					&IBFileBasic,
					sizeof(IBFileBasic),
					FileBasicInformation
				);
				//����ʧ��.�����ӡ��Ϣ
				if (!NT_SUCCESS(ntStatus))
					/*KdPrint(("NtDeleteFile()! ZwQueryInformationFile ,FileName:%wZ", uDeletePathName));*/
					return ntStatus;

				//�����ļ��Ļ�����Ϣ
				IBFileBasic.FileAttributes = FILE_ATTRIBUTE_NORMAL; //��������ΪĬ������

				ntStatus = ZwSetInformationFile(
					hFile,
					&ioStatus,
					&IBFileBasic,
					sizeof(IBFileBasic),
					FileBasicInformation); //���ҵ�FileBasic�����������õ�����ļ���

				ZwClose(hFile);		//����ɹ��ر��ļ����.
				if (!NT_SUCCESS(ntStatus))
					/*KdPrint(("NtDeleteFile()! ZwSetInformationFile"));*/
					return ntStatus;

				//���´����������Ϣ����ļ�.

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

	//����ǿ��ɾ���ļ� ͨ�� ZwSetInformationFile

	IBdelPostion.DeleteFile = TRUE; //�˱�־����ΪTRUE����ɾ��
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
						ntStatus = ZwReadFile(hReadFileHandle, NULL, NULL, NULL, &IoStatusBlock, pBuffer, (ULONG)FileInformation.EndOfFile.QuadPart, &ByteOffset, NULL);		//��ȡ����
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
	// (PASSIVE_LEVEL)���� IRQL �ȼ�ΪDISPATCH_LEVEL�������ؾɵ� IRQL
	// ��Ҫһ���ߵ�IRQL�����޸�
	*pirQl = KeRaiseIrqlToDpcLevel();
	ULONG_PTR cr0 = __readcr0(); // ������������ȡCr0�Ĵ�����ֵ, �൱��: mov eax,  cr0;

	// ����16λ��WPλ����0������д����
	cr0 &= ~0x10000; // ~ ��λȡ��
	_disable(); // ����жϱ��, �൱�� cli ָ��޸� IF��־λ
	__writecr0(cr0); // ��cr0������������д��Cr0�Ĵ����У��൱��: mov cr0, eax
}
// ��ԭCr0�Ĵ���
VOID RecoveryWP(
	IN PKIRQL pirQl
)
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000; // WP��ԭΪ1
	_disable(); // ����жϱ��, �൱�� cli ָ���� IF��־λ
	__writecr0(cr0); // ��cr0������������д��Cr0�Ĵ����У��൱��: mov cr0, eax

	// �ָ�IRQL�ȼ�
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
	(ULONG_PTR)&Message, //����
	(ULONG_PTR)&Title, //���Ǵ�˵�еĴ������...
	ShowOpt,
	0
	};

	if (pntStatus)
		*pntStatus = ExRaiseHardError(STATUS_SERVICE_NOTIFICATION | 0x10000000, 3, 3, &Parameters, ResponseOption, &Response);
	else
		ExRaiseHardError(STATUS_SERVICE_NOTIFICATION | 0x10000000, 3, 3, &Parameters, ResponseOption, &Response);

	return Response;
}