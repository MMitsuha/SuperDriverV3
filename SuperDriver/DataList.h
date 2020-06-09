#pragma once

#include "Includes.h"

typedef struct _DATA_LIST
{
	LIST_ENTRY ListEntry;
	LPVOID Buffer;
	SIZE_T Size;
}DATA_LIST, * PDATA_LIST;

BOOLEAN List_Add(
	PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsTail
);

BOOLEAN List_Show(
	CONST PLIST_ENTRY pListEntry
);

BOOLEAN List_Check(
	CONST PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsUserSize
);

BOOLEAN List_Delete(
	PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsUserSize
);

BOOLEAN List_DeleteAll(
	PLIST_ENTRY pListEntry
);

#define List_AddToTail(pListEntry, Buffer, Size) List_Add(pListEntry, Buffer, Size, TRUE)
#define List_AddToHead(pListEntry, Buffer, Size) List_Add(pListEntry, Buffer, Size, FALSE)

#define List_CheckWildcard(pListEntry, Buffer) List_Check(pListEntry, Buffer, 0, FALSE)
#define List_CheckNoWildcard(pListEntry, Buffer, Size) List_Check(pListEntry, Buffer, Size, TRUE)

#define List_DeleteWildcard(pListEntry, Buffer) List_Delete(pListEntry, Buffer, 0, FALSE)
#define List_DeleteNoWildcard(pListEntry, Buffer, Size) List_Delete(pListEntry, Buffer, Size, TRUE)