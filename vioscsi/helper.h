/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: helper.h
 *
 * Author(s):
 * Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * Virtio block device include module.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#ifndef ___HELPER_H___
#define ___HELPER_H___


#include <ntddk.h>
#include <storport.h>

#include "osdep.h"
#include "srbwrapper.h"
#include "virtio_pci.h"
#include "vioscsi.h"

BOOLEAN
SendSRB(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

BOOLEAN
SendTMF(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

BOOLEAN
SendVssControl(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
ShutDown(
    IN PVOID DeviceExtension
    );

BOOLEAN
DeviceReset(
    IN PVOID DeviceExtension
    );

BOOLEAN
ReportDriverVersion(
    IN PVOID DeviceExtension
    );

BOOLEAN
ReportSnapshotStatus(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN u64 Status
    );

VOID
GetScsiConfig(
    IN PVOID DeviceExtension
    );

BOOLEAN
InitVirtIODevice(
    IN PVOID DeviceExtension
    );

BOOLEAN
InitHW(
    IN PVOID DeviceExtension,
    IN PPORT_CONFIGURATION_INFORMATION ConfigInfo
    );

VOID
LogError(
    IN PVOID HwDeviceExtension,
    IN ULONG ErrorCode,
    IN ULONG UniqueId
    );

BOOLEAN
KickEvent(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEventNode event
    );

BOOLEAN
SynchronizedKickEventRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    );

VOID
VioScsiCompleteDpcRoutine(
    IN PSTOR_DPC  Dpc,
    IN PVOID Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

VOID
ProcessQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN BOOLEAN dpc
    );

VOID
//FORCEINLINE
VioScsiVQLock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    OUT PSTOR_LOCK_HANDLE LockHandle,
    IN BOOLEAN isr
    );

VOID
//FORCEINLINE
VioScsiVQUnlock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN PSTOR_LOCK_HANDLE LockHandle,
    IN BOOLEAN isr
    );

#ifdef ENABLE_WMI
typedef struct {
    USHORT Length;
    WCHAR Buffer[256];
} WMIString, *PWMIString;

VOID
WmiInitializeContext(IN PADAPTER_EXTENSION AdapterExtension);

BOOLEAN
WmiSrb(
    IN     PADAPTER_EXTENSION   AdapterExtension,
    IN OUT PSRB_TYPE            Srb);
#endif

VOID
//FORCEINLINE
HandleResponse(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSICmd cmd,
    IN int queue
    );

PVOID
VioScsiPoolAlloc(
    IN PVOID DeviceExtension,
    IN SIZE_T size
    );

extern VirtIOSystemOps VioScsiSystemOps;

#endif // ___HELPER_H___
