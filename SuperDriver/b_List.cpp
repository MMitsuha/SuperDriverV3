#include "LIST.h"

BOOLEAN AddContextToList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
)
{
	PLIST_LINK Target = ListEntry;
	while (Target->Next)
		Target = Target->Next;
	Target->lpContent = ExAllocatePoolWithTag(NonPagedPool, SizeOfContent, 'TSIL');
	if (!Target->lpContent)
		return FALSE;
	memcpy(Target->lpContent, lpContent, SizeOfContent);
	Target->SizeOfContent = SizeOfContent;
	Target->Next = (PLIST_LINK)ExAllocatePoolWithTag(NonPagedPool, sizeof(*(Target->Next)), 'TNEC');
	if (!Target->Next)
		return FALSE;
	InitListLink(Target->Next);
	return TRUE;
}

VOID ShowListHEX(
	IN PLIST_LINK ListEntry
)
{
	PLIST_LINK Target = ListEntry;
	while (Target->Next)
	{
		for (SIZE_T i = 0; i < Target->SizeOfContent; i++)
			KdPrint(("[+] [LIST] Content:%X ,Pointer:%p\n", ((PBYTE)Target->lpContent)[i], Target));

		Target = Target->Next;
	}
	return;
}

VOID ShowListWCHAR(
	IN PLIST_LINK ListEntry
)
{
	PLIST_LINK Target = ListEntry;
	while (Target->Next)
	{
		KdPrint(("[+] [LIST] Content:%S ,Pointer:%p\n", (PWCHAR)Target->lpContent, Target));

		Target = Target->Next;
	}
	return;
}

BOOLEAN CheckList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
)
{
	PLIST_LINK Target = ListEntry;
	while (Target->Next)
	{
		if (!memcmp(Target->lpContent, lpContent, SizeOfContent))
			return TRUE;

		Target = Target->Next;
	}
	return FALSE;
}

BOOLEAN CheckList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent
)
{
	PLIST_LINK Target = ListEntry;
	while (Target->Next)
	{
		if (!memcmp(Target->lpContent, lpContent, Target->SizeOfContent))
			return TRUE;

		Target = Target->Next;
	}
	return FALSE;
}

BOOLEAN DelContextFromList(
	IN PLIST_LINK ListEntry,
	IN LPVOID lpContent,
	IN SIZE_T SizeOfContent
)
{
	PLIST_LINK LastTarget = ListEntry;
	PLIST_LINK Target = ListEntry;
	BOOLEAN IsFirst = TRUE;
	while (Target->Next)
	{
		if (!memcmp(Target->lpContent, lpContent, SizeOfContent))
		{
			LastTarget->Next = Target->Next;
			ExFreePool(Target->lpContent);
			InitListLink(Target);
			if (!IsFirst)
				ExFreePool(Target);
			return TRUE;
		}

		IsFirst = FALSE;
		LastTarget = Target;
		Target = Target->Next;
	}
	return FALSE;
}

VOID DelAllList(
	IN PLIST_LINK ListEntry
)
{
	PLIST_LINK Target = ListEntry;
	PLIST_LINK LastTarget = ListEntry;
	while (Target->Next)
	{
		ExFreePoolWithTag(Target->lpContent, 'TNEC');

		LastTarget = Target;
		Target = Target->Next;

		if (ListEntry != LastTarget)
			ExFreePoolWithTag(LastTarget, 'TSIL');
	}
	if (Target != ListEntry)
		ExFreePoolWithTag(Target, 'TSIL');

	InitListLink(ListEntry);

	return;
}