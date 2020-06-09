#include "DataList.h"

BOOLEAN List_Add(
	PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsTail
)
{
	BOOLEAN bRet = FALSE;
	TRY_START

		PDATA_LIST pAddList = (PDATA_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(DATA_LIST), 'TSIL');		//分配链表主体内存
	if (pAddList)	//成功
	{
		pAddList->Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, 'FBTI');
		if (pAddList->Buffer)
		{
			pAddList->Size = Size;
			memcpy(pAddList->Buffer, Buffer, Size);
			if (IsTail)
				InsertTailList(pListEntry, &pAddList->ListEntry);
			else
				InsertHeadList(pListEntry, &pAddList->ListEntry);
			bRet = TRUE;
		}
		else
			ExFreePoolWithTag(pAddList, 'TSIL');
	}
	return bRet;

	TRY_END(bRet)
}

BOOLEAN List_Show(
	CONST PLIST_ENTRY pListEntry
)
{
	BOOLEAN bRet = FALSE;
	TRY_START

		if (!IsListEmpty(pListEntry))
		{
			PLIST_ENTRY pTarget = pListEntry->Flink;
			PDATA_LIST pDataTarget = NULL;
			while (pTarget != pListEntry)
			{
				pDataTarget = CONTAINING_RECORD(pTarget, DATA_LIST, ListEntry);
				PrintIfm("[LIST] DataPointer:%p ,DataSize:%I64u ,Data:", pDataTarget, pDataTarget->Size);
				for (SIZE_T i = 0; i < pDataTarget->Size; i++)
					KdPrint(("%X", ((PBYTE)pDataTarget->Buffer)[i]));
				KdPrint(("\n"));
				pTarget = pTarget->Flink;
				bRet = TRUE;
			}
		}
	return bRet;

	TRY_END(bRet)
}

BOOLEAN List_Check(
	CONST PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsUserSize
)
{
	BOOLEAN bRet = FALSE;
	TRY_START

		if (!IsListEmpty(pListEntry))
		{
			SIZE_T _Size = 0;
			PLIST_ENTRY pTarget = pListEntry->Flink;
			PDATA_LIST pDataTarget = NULL;
			while (pTarget != pListEntry)
			{
				pDataTarget = CONTAINING_RECORD(pTarget, DATA_LIST, ListEntry);
				if (IsUserSize)
					_Size = Size;
				else
					_Size = pDataTarget->Size;
				if (!memcmp(pDataTarget->Buffer, Buffer, _Size))
				{
					bRet = TRUE;
					break;
				}
				pTarget = pTarget->Flink;
			}
		}
	return bRet;

	TRY_END(bRet)
}

BOOLEAN List_Delete(
	PLIST_ENTRY pListEntry,
	LPVOID Buffer,
	SIZE_T Size,
	BOOLEAN IsUserSize
)
{
	BOOLEAN bRet = FALSE;
	TRY_START

		if (!IsListEmpty(pListEntry))
		{
			SIZE_T _Size = 0;
			PLIST_ENTRY pTarget = pListEntry->Flink;
			PDATA_LIST pDataTarget = NULL;
			while (pTarget != pListEntry)
			{
				pDataTarget = CONTAINING_RECORD(pTarget, DATA_LIST, ListEntry);
				if (IsUserSize)
					_Size = Size;
				else
					_Size = pDataTarget->Size;
				if (!memcmp(pDataTarget->Buffer, Buffer, _Size))
				{
					bRet = RemoveEntryList(pTarget);
					break;
				}
				pTarget = pTarget->Flink;
			}
		}
	return bRet;

	TRY_END(bRet)
}

BOOLEAN List_DeleteAll(
	PLIST_ENTRY pListEntry
)
{
	BOOLEAN bRet = FALSE;
	TRY_START

		PLIST_ENTRY pTarget = NULL;
	PDATA_LIST pDataTarget = NULL;
	while (!IsListEmpty(pListEntry))
	{
		//从尾部删除一个元素
		pTarget = RemoveHeadList(pListEntry); //返回删除结构中ListEntry的位置
		pDataTarget = CONTAINING_RECORD(pTarget, DATA_LIST, ListEntry);
		ExFreePoolWithTag(pDataTarget->Buffer, 'FBTI');
		ExFreePoolWithTag(pDataTarget, 'TSIL');
		bRet = TRUE;
	}
	return bRet;

	TRY_END(bRet)
}