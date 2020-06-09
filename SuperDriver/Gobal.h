#pragma once

#include "Includes.h"
#include "../../Public.h"

extern PDEVICE_OBJECT g_pCreateDevice;
extern UNICODE_STRING g_usDevName;
extern UNICODE_STRING g_usSymName;

/**********************************************************/

extern LIST_ENTRY g_KillKeyList;

//------------------------------

extern PVOID g_FileCallbackHandle;
extern LIST_ENTRY g_ProtDirList;
extern LIST_ENTRY g_ProtFileList;

//-------------------------------

extern PVOID g_ProcKillCallbackHandle;
extern LIST_ENTRY g_KillProcList;				//Â·¾¶
extern LIST_ENTRY g_ProtProcList;				//PID
extern BOOLEAN g_KillAllProc_Switch;

//------------------------------------

extern BOOLEAN g_KillAllSys_Switch;
extern LIST_ENTRY g_KillSysList;
extern BOOLEAN g_KillAllDll_Switch;
extern LIST_ENTRY g_KillDllList;

//---------------------------------------

extern BOOLEAN g_KillAllThr_Switch;

//------------------------------------------

extern LARGE_INTEGER g_RegCallbackHandle;
extern BOOLEAN g_ProtSelfReg_Switch;

//-------------------------------------------

extern BOOLEAN g_ProtAllFile_Switch;

//-------------------------------------------

extern UNICODE_STRING g_uniRegistryPath;