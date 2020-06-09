#include "Includes.h"

#ifdef _WIN64

#define GetOffsetAddress(FuncAddr,ServiceTableBase) ((ULONG)((UINT64)FuncAddr - (UINT64)ServiceTableBase) << 4)

#pragma pack(1)
typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;          // SSDT基址
	PVOID ServiceCounterTableBase; // SSDT中服务被调用次数计数器
	ULONGLONG NumberOfService;     // SSDT服务个数
	PVOID ParamTableBase;          // 系统服务参数表基址
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
	PULONG ServiceTableBase;          // SSDT基址
	PULONG ServiceCounterTableBase;// SSDT中服务被调用次数计数器
	ULONG NumberOfService;         // SSDT服务个数
	PUCHAR ParamTableBase;          // 系统服务参数表基址
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