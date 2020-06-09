#include "IRPCtlFile.h"

/*
//
// 自行实现的InitUnicodeString
//

errno_t
MyInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_  PCWSTR SourceString)
{
	USHORT Size = (USHORT)(sizeof(WCHAR) * (wcsnlen_s(SourceString, USHRT_MAX / sizeof(WCHAR)) + 1));
	DestinationString->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, Size, 'US');
	RtlZeroMemory(DestinationString->Buffer, Size);
	DestinationString->MaximumLength = DestinationString->Length = Size;
	return memcpy_s(DestinationString->Buffer, Size, SourceString, Size);
}

VOID
MyFreeUnicodeString(
	_In_ PUNICODE_STRING SourceString)
{
	ExFreePoolWithTag(SourceString->Buffer, 'US');
	RtlZeroMemory(SourceString, sizeof(UNICODE_STRING));
	return;
}
*/

//
// Function start.
//

NTSTATUS
FASTCALL
_IoCallDriver(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp,
	IN PIO_STACK_LOCATION IrpSp
)
{
	PDRIVER_OBJECT DriverObject;
	DriverObject = pDeviceObject->DriverObject;
	pIrp->CurrentLocation--;
	if (pIrp->CurrentLocation <= 0)
		KeBugCheckEx(NO_MORE_IRP_STACK_LOCATIONS, (ULONG_PTR)pIrp, 0, 0, 0);
	pIrp->Tail.Overlay.CurrentStackLocation = IrpSp;
	IrpSp->DeviceObject = pDeviceObject;
	return DriverObject->MajorFunction[IrpSp->MajorFunction](pDeviceObject, pIrp);
}

NTSTATUS
IrpCompletionRoutine(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context)
{
	*Irp->UserIosb = Irp->IoStatus;
	if (Irp->UserEvent)
		KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, 0);
	if (Irp->MdlAddress)
	{
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}
	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
GetDriveObject(
	IN PUNICODE_STRING pDriveName,
	OUT PDEVICE_OBJECT* pDeviceObject,
	OUT PDEVICE_OBJECT* pReadDevice,
	PIO_STATUS_BLOCK pIoStatus)
{
	//定义变量
	NTSTATUS ntStatus = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES AttributesObject = { 0 };
	HANDLE DeviceHandle = NULL;
	PFILE_OBJECT pFileObject = NULL;

	//参数效验
	if (pDriveName == NULL || pDeviceObject == NULL || pReadDevice == NULL)
		return STATUS_INVALID_PARAMETER;

	//打开设备
	InitializeObjectAttributes(&AttributesObject, pDriveName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntStatus = IoCreateFile(&DeviceHandle, SYNCHRONIZE | FILE_READ_ACCESS | FILE_WRITE_ACCESS, &AttributesObject, pIoStatus, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;

	//获取文件对象
	ntStatus = ObReferenceObjectByHandle(DeviceHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode, (LPVOID*)&pFileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(DeviceHandle);
		return ntStatus;
	}

	//效验结果
	if (pFileObject->Vpb == 0 || pFileObject->Vpb->RealDevice == NULL)
	{
		ObDereferenceObject(pFileObject);
		ZwClose(DeviceHandle);
		return STATUS_UNSUCCESSFUL;
	}

	//设置变量
	*pDeviceObject = pFileObject->Vpb->DeviceObject;
	*pReadDevice = pFileObject->Vpb->RealDevice;

	ObDereferenceObject(pFileObject);
	ZwClose(DeviceHandle);

	return ntStatus;
}

NTSTATUS
IrpCreateFile(
	OUT PFILE_OBJECT* pFileObject,
	IN ACCESS_MASK  DesiredAccess,
	IN PUNICODE_STRING  pFilePath,
	OUT PIO_STATUS_BLOCK  pIoStatusBlock,
	IN PLARGE_INTEGER  pAllocationSize  OPTIONAL,
	IN ULONG  FileAttributes,
	IN ULONG  ShareAccess,
	IN ULONG  CreateDisposition,
	IN ULONG  CreateOptions,
	IN PVOID  EaBuffer  OPTIONAL,
	IN ULONG  EaLength)
{
	//定义变量
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIRP pIrp = NULL;
	KEVENT kEvent = { 0 };
	ACCESS_STATE AccessState = { 0 };
	AUX_ACCESS_DATA AuxData = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PFILE_OBJECT  pNewFileObject = NULL;
	IO_SECURITY_CONTEXT SecurityContext = { 0 };
	PIO_STACK_LOCATION IrpSp = NULL;
	PDEVICE_OBJECT pDeviceObject = NULL;
	PDEVICE_OBJECT pReadDevice = NULL;
	UNICODE_STRING uniDriveName = { 0 };
	WCHAR wszDriveName[8] = { 0 };
	PWCHAR pFileNameBuf = NULL;

	//参数效验
	if (pFilePath == NULL || pIoStatusBlock == NULL || pFileObject == NULL || pFilePath->Length <= 6)
		return STATUS_INVALID_PARAMETER;

	RtlCopyMemory(wszDriveName, pFilePath->Buffer, 7 * sizeof(WCHAR));
	RtlInitUnicodeString(&uniDriveName, wszDriveName);

	//获取设备对象
	ntStatus = GetDriveObject(&uniDriveName, &pDeviceObject, &pReadDevice, pIoStatusBlock);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;

	//参数效验
	if (pDeviceObject == NULL || pReadDevice == NULL || pDeviceObject->StackSize <= 0)
		return STATUS_UNSUCCESSFUL;

	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, NULL);
	ntStatus = ObCreateObject(KernelMode, *IoFileObjectType, &ObjectAttributes, KernelMode, NULL, sizeof(FILE_OBJECT), 0, 0, (LPVOID*)&pNewFileObject);
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;

	ntStatus = SeCreateAccessState(&AccessState, &AuxData, FILE_ALL_ACCESS, IoGetFileObjectGenericMapping());
	if (!NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(pNewFileObject);
		return ntStatus;
	}

	SecurityContext.SecurityQos = NULL;
	SecurityContext.AccessState = &AccessState;
	SecurityContext.DesiredAccess = DesiredAccess; //FILE_ALL_ACCESS;       // DELETE
	SecurityContext.FullCreateOptions = 0;

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);
	RtlZeroMemory(pNewFileObject, sizeof(FILE_OBJECT));
	pNewFileObject->Type = IO_TYPE_FILE;
	pNewFileObject->Size = sizeof(FILE_OBJECT);
	pNewFileObject->DeviceObject = pReadDevice;
	pNewFileObject->Flags = FO_SYNCHRONOUS_IO;

	SIZE_T SizeOfpFileNameBuf = sizeof(WCHAR) * (wcsnlen_s(&(pFilePath->Buffer[6]), USHRT_MAX / sizeof(WCHAR)) + 1);
	pFileNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, SizeOfpFileNameBuf, 'FP');
	if (pFileNameBuf == NULL) return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(pFileNameBuf, SizeOfpFileNameBuf);
	RtlCopyMemory(pFileNameBuf, &(pFilePath->Buffer[6]), SizeOfpFileNameBuf);
	RtlInitUnicodeString(&pNewFileObject->FileName, pFileNameBuf);       //地址不能是局部变量地址
	KeInitializeEvent(&pNewFileObject->Lock, SynchronizationEvent, FALSE);
	KeInitializeEvent(&pNewFileObject->Event, NotificationEvent, FALSE);

	pIrp = IoAllocateIrp(pDeviceObject->StackSize, FALSE);
	if (pIrp == NULL)
	{
		ExFreePoolWithTag(pFileNameBuf, 'FP');
		ObDereferenceObject(pNewFileObject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pIrp->MdlAddress = NULL;
	pIrp->AssociatedIrp.SystemBuffer = EaBuffer;
	pIrp->Flags = IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API;
	pIrp->RequestorMode = KernelMode;
	pIrp->UserIosb = pIoStatusBlock;
	pIrp->UserEvent = &kEvent;
	pIrp->PendingReturned = FALSE;
	pIrp->Cancel = FALSE;
	pIrp->CancelRoutine = NULL;
	pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pIrp->Tail.Overlay.AuxiliaryBuffer = NULL;
	pIrp->Tail.Overlay.OriginalFileObject = pNewFileObject;

	IrpSp = IoGetNextIrpStackLocation(pIrp);
	if (IrpSp == NULL)
	{
		ExFreePoolWithTag(pFileNameBuf, 'FP');
		IoFreeIrp(pIrp);
		ObDereferenceObject(pNewFileObject);
		return ntStatus;
	}

	IrpSp->MajorFunction = IRP_MJ_CREATE;
	IrpSp->DeviceObject = pDeviceObject;
	IrpSp->FileObject = pNewFileObject;
	IrpSp->Parameters.Create.SecurityContext = &SecurityContext;
	IrpSp->Parameters.Create.Options = (CreateDisposition << 24) | CreateOptions;
	IrpSp->Parameters.Create.FileAttributes = (USHORT)FileAttributes;
	IrpSp->Parameters.Create.ShareAccess = (USHORT)ShareAccess;
	IrpSp->Parameters.Create.EaLength = EaLength;

	IoSetCompletionRoutine(pIrp, IrpCompletionRoutine, 0, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(pDeviceObject, pIrp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);
	ntStatus = pIoStatusBlock->Status;

	if (!NT_SUCCESS(ntStatus))
	{
		pNewFileObject->DeviceObject = NULL;
		ObDereferenceObject(pNewFileObject);
	}
	else
	{
		//设置变量
		InterlockedIncrement(&pNewFileObject->DeviceObject->ReferenceCount);
		if (pNewFileObject->Vpb)
			InterlockedIncrement64((volatile LONG64*)&pNewFileObject->Vpb->ReferenceCount);
		*pFileObject = pNewFileObject;
	}

	ExFreePoolWithTag(pFileNameBuf, 'FP');
	return ntStatus;
}

NTSTATUS
IrpClose(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject
)
{
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK  IoStatusBlock;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	Irp->UserEvent = &kEvent;
	Irp->UserIosb = &IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_CLEANUP;
	IrpSp->FileObject = FileObject;

	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);

	ntStatus = IoStatusBlock.Status;
	if (!NT_SUCCESS(ntStatus))
	{
		IoFreeIrp(Irp);
		return ntStatus;
	}

	KeClearEvent(&kEvent);
	IoReuseIrp(Irp, STATUS_SUCCESS);

	Irp->UserEvent = &kEvent;
	Irp->UserIosb = &IoStatusBlock;
	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->AssociatedIrp.SystemBuffer = (PVOID)NULL;
	Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_CLOSE;
	IrpSp->FileObject = FileObject;

	if (FileObject->Vpb && !(FileObject->Flags & FO_DIRECT_DEVICE_OPEN))
	{
		InterlockedDecrement((volatile LONG*)&FileObject->Vpb->ReferenceCount);
		FileObject->Flags |= FO_FILE_OPEN_CANCELLED;
	}

	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);

	IoFreeIrp(Irp);

	ntStatus = IoStatusBlock.Status;
	return ntStatus;
}

NTSTATUS
IrpDeleteFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PIO_STATUS_BLOCK IoStatus)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	FILE_BASIC_INFORMATION BasiFileInformation = { 0 };
	BasiFileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	ntStatus = IrpSetInformationFile(DeviceObject, FileObject, IoStatus, &BasiFileInformation, sizeof(BasiFileInformation), FileBasicInformation, FALSE);
	if (NT_SUCCESS(ntStatus))
	{
		FILE_DISPOSITION_INFORMATION DespFileInformation = { 0 };
		DespFileInformation.DeleteFile = TRUE;

		FileObject->SectionObjectPointer->ImageSectionObject = 0;
		FileObject->SectionObjectPointer->DataSectionObject = 0;

		ntStatus = IrpSetInformationFile(DeviceObject, FileObject, IoStatus, &DespFileInformation, sizeof(DespFileInformation), FileDispositionInformation, FALSE);
	}

	return ntStatus;
}

NTSTATUS
IrpQueryDirectoryFile(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	OUT PVOID  FileInformation,
	IN ULONG  Length,
	IN FILE_INFORMATION_CLASS  FileInformationClass,
	IN PUNICODE_STRING  FileName  OPTIONAL)
{
	NTSTATUS ntStatus;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	RtlZeroMemory(FileInformation, Length);
	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->UserBuffer = FileInformation;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Overlay.AsynchronousParameters.UserApcRoutine = (PIO_APC_ROUTINE)NULL;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	Irp->Tail.Overlay.CurrentStackLocation = IrpSp;
	IrpSp->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
	IrpSp->MinorFunction = IRP_MN_QUERY_DIRECTORY;
	IrpSp->FileObject = FileObject;
	IrpSp->Flags = SL_RESTART_SCAN;
	IrpSp->Parameters.QueryDirectory.Length = Length;
	IrpSp->Parameters.QueryDirectory.FileName = FileName;
	IrpSp->Parameters.QueryDirectory.FileInformationClass = FileInformationClass;

	IoSetCompletionRoutine(Irp, IrpCompletionRoutine, 0, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);

	return IoStatusBlock->Status;
}

NTSTATUS
IrpQueryInformationFile(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	OUT PVOID  FileInformation,
	IN ULONG  Length,
	IN FILE_INFORMATION_CLASS  FileInformationClass)
{
	NTSTATUS ntStatus;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	RtlZeroMemory(FileInformation, Length);
	Irp->AssociatedIrp.SystemBuffer = FileInformation;
	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.QueryFile.Length = Length;
	IrpSp->Parameters.QueryFile.FileInformationClass = FileInformationClass;

	IoSetCompletionRoutine(Irp, IrpCompletionRoutine, 0, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);

	return IoStatusBlock->Status;
}

NTSTATUS
IrpSetInformationFile(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PVOID  FileInformation,
	IN ULONG  Length,
	IN FILE_INFORMATION_CLASS  FileInformationClass,
	IN BOOLEAN  ReplaceIfExists)
{
	NTSTATUS ntStatus;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	Irp->AssociatedIrp.SystemBuffer = FileInformation;
	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	if (IrpSp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	IrpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.SetFile.ReplaceIfExists = ReplaceIfExists;
	IrpSp->Parameters.SetFile.FileObject = FileObject;
	IrpSp->Parameters.SetFile.AdvanceOnly = FALSE;
	IrpSp->Parameters.SetFile.Length = Length;
	IrpSp->Parameters.SetFile.FileInformationClass = FileInformationClass;

	IoSetCompletionRoutine(Irp, IrpCompletionRoutine, 0, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);

	return IoStatusBlock->Status;
}

NTSTATUS
IrpReadFile(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	OUT PVOID  Buffer,
	IN ULONG  Length,
	IN PLARGE_INTEGER  ByteOffset  OPTIONAL)
{
	NTSTATUS ntStatus;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	if (ByteOffset == NULL)
	{
		if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
			return STATUS_INVALID_PARAMETER;
		ByteOffset = &FileObject->CurrentByteOffset;
	}

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(Buffer, Length);
	if (FileObject->DeviceObject->Flags & DO_BUFFERED_IO)
	{
		Irp->AssociatedIrp.SystemBuffer = Buffer;
	}
	else if (FileObject->DeviceObject->Flags & DO_DIRECT_IO)
	{
		Irp->MdlAddress = IoAllocateMdl(Buffer, Length, 0, 0, 0);
		if (Irp->MdlAddress == NULL)
		{
			IoFreeIrp(Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		MmBuildMdlForNonPagedPool(Irp->MdlAddress);
	}
	else
	{
		Irp->UserBuffer = Buffer;
	}

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_READ_OPERATION;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_READ;
	IrpSp->MinorFunction = IRP_MN_NORMAL;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.Read.Length = Length;
	IrpSp->Parameters.Read.ByteOffset = *ByteOffset;

	IoSetCompletionRoutine(Irp, IrpCompletionRoutine, 0, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);
	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);

	return IoStatusBlock->Status;
}

NTSTATUS
IrpWriteFile(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PFILE_OBJECT  FileObject,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PVOID  Buffer,
	IN ULONG  Length,
	IN PLARGE_INTEGER  ByteOffset  OPTIONAL)
{
	NTSTATUS ntStatus;
	PIRP Irp;
	KEVENT kEvent;
	PIO_STACK_LOCATION IrpSp;

	if (ByteOffset == NULL)
	{
		if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
			return STATUS_INVALID_PARAMETER;
		ByteOffset = &FileObject->CurrentByteOffset;
	}

	Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
	if (Irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

	if (FileObject->DeviceObject->Flags & DO_BUFFERED_IO)
	{
		Irp->AssociatedIrp.SystemBuffer = Buffer;
	}
	else
	{
		Irp->MdlAddress = IoAllocateMdl(Buffer, Length, 0, 0, 0);
		if (Irp->MdlAddress == NULL)
		{
			IoFreeIrp(Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		MmBuildMdlForNonPagedPool(Irp->MdlAddress);
	}

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_WRITE_OPERATION;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_WRITE;
	IrpSp->MinorFunction = IRP_MN_NORMAL;
	IrpSp->DeviceObject = DeviceObject;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.Write.Length = Length;
	IrpSp->Parameters.Write.ByteOffset = *ByteOffset;

	IoSetCompletionRoutine(Irp, IrpCompletionRoutine, NULL, TRUE, TRUE, TRUE);
	ntStatus = _IoCallDriver(DeviceObject, Irp, IrpSp);

	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, NULL);

	return IoStatusBlock->Status;
}

NTSTATUS
IrpAutoDeleteFile(
	IN PWCHAR pFilePath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING usFilePath = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	PFILE_OBJECT pFileObject = NULL;
	RtlInitUnicodeString(&usFilePath, pFilePath);

	ntStatus = IrpCreateFile(&pFileObject, GENERIC_ALL | SYNCHRONIZE, &usFilePath, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, 0, NULL, 0);
	if (NT_SUCCESS(ntStatus))
	{
		PDEVICE_OBJECT pDeviceObject = IoGetRelatedDeviceObject(pFileObject);
		ntStatus = IrpDeleteFile(pDeviceObject, pFileObject, &IoStatusBlock);
		IrpClose(pDeviceObject, pFileObject);
	}
	return ntStatus;
}

NTSTATUS
IrpAutoProtectFile(
	IN PWCHAR pFilePath)
{
	UNICODE_STRING usFilePath = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	PFILE_OBJECT pFileObject = NULL;
	RtlInitUnicodeString(&usFilePath, pFilePath);

	return IrpCreateFile(&pFileObject, FILE_ALL_ACCESS, &usFilePath, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, 0, NULL, 0);
}