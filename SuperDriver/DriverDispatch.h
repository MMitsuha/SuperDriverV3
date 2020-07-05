#pragma once

#include "Includes.h"
#include "Undisclosed.h"
#include "../../Public.h"
#include "Gobal.h"
#include "DataList.h"
#include "FsdHook.h"
#include "Monitor.h"
#include "IRPCtlFile.h"

NTSTATUS DefaultDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS CreateDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS CloseDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS IoControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS WriteDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS ReadDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS PointDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);