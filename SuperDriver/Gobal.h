#pragma once

#include "Includes.h"
#include "DataList.h"
#include "../../Public.h"

extern PDEVICE_OBJECT g_pCreateDevice;
extern UNICODE_STRING g_usDevName;
extern UNICODE_STRING g_usSymName;

/**********************************************************/

extern DATA_LIST_ENTRY g_KillKeyList;

//------------------------------

extern PVOID g_FileCallbackHandle;
extern DATA_LIST_ENTRY g_ProtDirList;
extern DATA_LIST_ENTRY g_ProtFileList;

//-------------------------------

extern PVOID g_ProcKillCallbackHandle;
extern DATA_LIST_ENTRY g_KillProcList;				//Â·¾¶
extern DATA_LIST_ENTRY g_ProtProcList;				//PID
extern BOOLEAN g_KillAllProc_Switch;

//------------------------------------

extern BOOLEAN g_KillAllSys_Switch;
extern DATA_LIST_ENTRY g_KillSysList;
extern BOOLEAN g_KillAllDll_Switch;
extern DATA_LIST_ENTRY g_KillDllList;

//---------------------------------------

extern BOOLEAN g_KillAllThr_Switch;

//------------------------------------------

extern LARGE_INTEGER g_RegCallbackHandle;
extern BOOLEAN g_ProtSelfReg_Switch;

//-------------------------------------------

extern BOOLEAN g_ProtAllFile_Switch;

//-------------------------------------------

extern UNICODE_STRING g_uniRegistryPath;