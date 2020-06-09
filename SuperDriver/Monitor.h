#pragma once

#include "Functions.h"
#include "Undisclosed.h"
#include "Gobal.h"
#include "DataList.h"
#include "../../Public.h"

NTSTATUS Mon_CreateProcMonEx(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateProcMon(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateMoudleMon(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateThrMon(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateRegMon(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateFileMon(
	IN BOOLEAN bCreate
);

NTSTATUS Mon_CreateProcKillMon(
	IN BOOLEAN bCreate
);