#include "SSDT.h"
#include "Functions.h"

NTSTATUS DllFileMap(
	UNICODE_STRING ustrDllFileName,
	PHANDLE phFile,
	PHANDLE phSection,
	PVOID* ppBaseAddress
)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	// �� DLL �ļ�, ����ȡ�ļ����
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		PrintErr("[DllFileMap] ZwOpenFile Fail! Errorcode:%X\n", status);
		return status;
	}
	// ����һ���ڶ���, �� PE �ṹ�е� SectionALignment ��С����ӳ���ļ�
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		PrintErr("[DllFileMap] ZwCreateSection Fail! Errorcode:%X\n", status);
		return status;
	}
	// ӳ�䵽�ڴ�
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		PrintErr("[DllFileMap] ZwMapViewOfSection Fail! Errorcode:%X\n", status);
		return status;
	}
	// ��������
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;
	return status;
}

// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
ULONG GetIndexFromExportTable(
	PVOID pBaseAddress,
	PCHAR pszFunctionName
)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// �����Ƶĵ�����������
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// �����������Ƶ�ַ��
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// ��ʼ����������
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// �ж��Ƿ���ҵĺ���
		if (0 == _strnicmp(pszFunctionName, lpName, strnlen(pszFunctionName, MAX_PATH)))
		{
			// ��ȡ����������ַ
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + (UINT64)2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + (UINT64)4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// ��ȡ SSDT ���� Index
#ifdef _WIN64
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 4);
#else
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
#endif
			break;
		}
	}
	return ulFunctionIndex;
}

// �� ntdll.dll �л�ȡ SSDT ����������
ULONG GetSSDTFunctionIndex(
	UNICODE_STRING ustrDllFileName,
	PCHAR pszFunctionName
)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	// �ڴ�ӳ���ļ�
	status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		PrintErr("[GetSSDTFunctionIndex] DllFileMap Error! Errorcode:%X\n", status);
		return ulFunctionIndex;
	}
	// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);
	// �ͷ�
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);
	return ulFunctionIndex;
}

// ����������, �� KiSystemCall64 �л�ȡ SSDT ��ַ
PVOID GetSSDTAddress(
	VOID
)
{
	PVOID pServiceDescriptorTable = NULL;
	PVOID pKiSystemCall64 = NULL;
	UCHAR ulCode1 = 0;
	UCHAR ulCode2 = 0;
	UCHAR ulCode3 = 0;
	// ע��ʹ���з�������
	LONG lOffset = 0;
	// ��ȡ KiSystemCall64 ������ַ
	pKiSystemCall64 = (PVOID)__readmsr(0xC0000082);
	// ���������� 4C8D15
	for (ULONG i = 0; i < 1024; i++)
	{
		// ��ȡ�ڴ�����
		ulCode1 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i));
		ulCode2 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i + 1));
		ulCode3 = *((PUCHAR)((PUCHAR)pKiSystemCall64 + i + 2));
		// �ж�
		if (0x4C == ulCode1 &&
			0x8D == ulCode2 &&
			0x15 == ulCode3)
		{
			// ��ȡƫ��
			lOffset = *((PLONG)((PUCHAR)pKiSystemCall64 + i + 3));
			// ����ƫ�Ƽ����ַ
			pServiceDescriptorTable = (PVOID)(((PUCHAR)pKiSystemCall64 + i) + 7 + lOffset);
			break;
		}
	}
	return pServiceDescriptorTable;
}

#ifdef _WIN64

// ��ȡ SSDT ������ַ
PVOID GetSSDTFunction(
	PCHAR pszFunctionName
)
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;
	PVOID pFunctionAddress = NULL;
	PSSDTEntry pServiceDescriptorTable = NULL;
	ULONG ulOffset = 0;
	RtlInitUnicodeString(&ustrDllFileName, L"\\SystemRoot\\System32\\ntdll.dll");
	// �� ntdll.dll �л�ȡ SSDT ����������
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, pszFunctionName);
	// ����������, �� KiSystemCall64 �л�ȡ SSDT ��ַ
	pServiceDescriptorTable = (PSSDTEntry)GetSSDTAddress();
	// ����������, ��SSDT���л�ȡ��Ӧ����ƫ�Ƶ�ַ�������������ַ
	ulOffset = pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex] >> 4;
	pFunctionAddress = (PVOID)((PUCHAR)pServiceDescriptorTable->ServiceTableBase + ulOffset);
	// ��ʾ
	PrintSuc("[GetSSDTFunction x64] FuncName:%s ,SSDT Addr:%p ,Index:%ul ,Address:%p\n", pszFunctionName, pServiceDescriptorTable, ulSSDTFunctionIndex, pFunctionAddress);
	return pFunctionAddress;
}

VOID TransitionJump(
	LPVOID OriFunc,
	LPVOID TargetFunc
)
{
	KIRQL irQl = 0;
	UCHAR JmpCode[12] = { 0x48,0xB8,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0xFF,0xE0 };
	UINT64 MyFunc = (UINT64)TargetFunc;
	memcpy(JmpCode + 2, &MyFunc, 8);
	RemoveWP(&irQl);
	memset(OriFunc, 0x90, 15);
	memcpy(OriFunc, JmpCode, 12);
	RecoveryWP(&irQl);
	return;
}

VOID HookSSDT(
	IN LPSTR OriFuncName,
	OUT LPVOID* OriAddr,
	IN LPVOID TargetFunc,
	IN LPVOID DeathFunc
)
{
	PSSDTEntry pServiceDescriptorTable = (PSSDTEntry)GetSSDTAddress();
	UNICODE_STRING ustrDllFileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, OriFuncName);
	TransitionJump(DeathFunc, TargetFunc);
	*OriAddr = GetSSDTFunction(OriFuncName);
	KIRQL irQl = 0;
	RemoveWP(&irQl);
	pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex] = GetOffsetAddress(DeathFunc, pServiceDescriptorTable->ServiceTableBase);
	RecoveryWP(&irQl);
	return;
}

VOID UnhookSSDT(
	LPSTR OriFuncName,
	LPVOID OriAddr
)
{
	PSSDTEntry pServiceDescriptorTable = (PSSDTEntry)GetSSDTAddress();
	UNICODE_STRING ustrDllFileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, OriFuncName);
	KIRQL irQl = 0;
	RemoveWP(&irQl);
	pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex] = GetOffsetAddress(OriAddr, pServiceDescriptorTable->ServiceTableBase);
	RecoveryWP(&irQl);
	return;
}

#else

PVOID GetSSDTFunction(
	PCHAR pszFunctionName
)
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;
	PVOID pFunctionAddress = NULL;
	RtlInitUnicodeString(&ustrDllFileName, L"\\SystemRoot\\System32\\ntdll.dll");
	// �� ntdll.dll �л�ȡ SSDT ����������
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, pszFunctionName);
	// ����������, ��SSDT���л�ȡ��Ӧ������ַ
	pFunctionAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
	// ��ʾ
	PrintSuc("[GetSSDTFunction x86] FuncName:%s ,Index:%ul ,Address:%p\n", pszFunctionName, ulSSDTFunctionIndex, pFunctionAddress);
	return pFunctionAddress;
}

VOID HookSSDT(
	LPSTR OriFuncName,
	LPVOID* OriAddr,
	LPVOID TargetFunc
)
{
	UNICODE_STRING ustrDllFileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, OriFuncName);
	*OriAddr = GetSSDTFunction(OriFuncName);
	KIRQL irQl = 0;
	RemoveWP(&irQl);
	KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex] = (ULONG)TargetFunc;
	RecoveryWP(&irQl);
	return;
}

VOID UnhookSSDT(
	LPSTR OriFuncName,
	LPVOID OriAddr
)
{
	PSSDTEntry pServiceDescriptorTable = (PSSDTEntry)GetSSDTAddress();
	UNICODE_STRING ustrDllFileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, OriFuncName);
	KIRQL irQl = 0;
	RemoveWP(&irQl);
	pServiceDescriptorTable->ServiceTableBase[ulSSDTFunctionIndex] = (ULONG)OriAddr;
	RecoveryWP(&irQl);
	return;
}

#endif // _WIN64