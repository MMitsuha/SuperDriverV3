#pragma once

#include "Includes.h"

#define InitListLink(lpList) RtlZeroMemory((lpList),sizeof(*(lpList)))

typedef struct _LIST_LINK_ {
	struct _LIST_LINK_* Next;
	LPVOID lpContent;
	SIZE_T SizeOfContent;
}LIST_LINK, * PLIST_LINK;

BOOLEAN AddContextToList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
);

VOID ShowListHEX(
	IN PLIST_LINK ListEntry
);

VOID ShowListWCHAR(
	IN PLIST_LINK ListEntry
);

BOOLEAN CheckList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
);

BOOLEAN CheckList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent
);

BOOLEAN DelContextFromList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
);

VOID DelAllList(
	IN PLIST_LINK ListEntry
);