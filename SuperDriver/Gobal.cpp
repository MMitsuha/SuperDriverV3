#include "Gobal.h"

PDEVICE_OBJECT g_pCreateDevice = NULL;
UNICODE_STRING g_usDevName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING g_usSymName = RTL_CONSTANT_STRING(SYMBOLIC_LINK_NAME);

/**************************************************************************/

LIST_ENTRY g_KillKeyList = { 0 };

//-------------------------------------

PVOID g_FileCallbackHandle = NULL;
LIST_ENTRY g_ProtDirList = { 0 };
LIST_ENTRY g_ProtFileList = { 0 };

//------------------------------------

PVOID g_ProcKillCallbackHandle = NULL;
LIST_ENTRY g_KillProcList = { 0 };
LIST_ENTRY g_ProtProcList = { 0 };
BOOLEAN g_KillAllProc_Switch = FALSE;

//------------------------------------

BOOLEAN g_KillAllSys_Switch = FALSE;
LIST_ENTRY g_KillSysList = { 0 };
BOOLEAN g_KillAllDll_Switch = FALSE;
LIST_ENTRY g_KillDllList = { 0 };

//-------------------------------------

BOOLEAN g_KillAllThr_Switch = FALSE;

//-----------------------------------

LARGE_INTEGER g_RegCallbackHandle = { 0 };
BOOLEAN g_ProtSelfReg_Switch = FALSE;

//----------------------------------------

BOOLEAN g_ProtAllFile_Switch = FALSE;

//----------------------------------------

UNICODE_STRING g_uniRegistryPath = { 0 };