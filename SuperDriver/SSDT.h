#include "Includes.h"

#ifdef _WIN64

#define GetOffsetAddress(FuncAddr,ServiceTableBase) ((ULONG)((UINT64)FuncAddr - (UINT64)ServiceTableBase) << 4)

#pragma pack(1)
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;          // SSDT��ַ
	PVOID ServiceCounterTableBase; // SSDT�з��񱻵��ô���������
	ULONGLONG NumberOfService;     // SSDT�������
	PVOID ParamTableBase;          // ϵͳ����������ַ
}SSDTEntry, * PSSDTEntry;
#pragma pack()

VOID HookSSDT(
	LPSTR OriFuncName,
	LPVOID* OriAddr,
	LPVOID TargetFunc,
	LPVOID DeathFunc
);

#else

#pragma pack(1)
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;          // SSDT��ַ
	PULONG ServiceCounterTableBase;// SSDT�з��񱻵��ô���������
	ULONG NumberOfService;         // SSDT�������
	PUCHAR ParamTableBase;          // ϵͳ����������ַ
}SSDTEntry, * PSSDTEntry;
#pragma pack()

#ifdef __cplusplus
EXTERN_C_START
#endif // _cplusplus

extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;

#ifdef __cplusplus
EXTERN_C_END
#endif // _cplusplus

VOID HookSSDT(
	LPSTR OriFuncName,
	LPVOID* OriAddr,
	LPVOID TargetFunc
);

#endif // _WIN64

PVOID GetSSDTFunction(
	PCHAR pszFunctionName
);