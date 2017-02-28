/**********************************************************************
 * Copyright (c) 2008-2016 Red Hat, Inc.
 *
 * File: virtio_stor_hw_helper.h
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
#ifndef ___VIOSTOR_HW_HELPER_H___
#define ___VIOSTOR_HW_HELPER_H___


#include <ntddk.h>

#ifdef USE_STORPORT
#define STOR_USE_SCSI_ALIASES
#include <storport.h>
#else
#include <scsi.h>
#endif

#include "osdep.h"
#include "virtio_pci.h"
#include "virtio.h"
#include "virtio_stor.h"

#if (NTDDI_VERSION > NTDDI_WIN7)
#include <srbhelper.h>

FORCEINLINE ULONG
SrbGetCdbLenght(_In_ PVOID Srb) {
    ULONG CdbLen32 = 0;
    UCHAR CdbLen8 = 0;
    SrbGetScsiData(Srb, &CdbLen8, &CdbLen32, NULL, NULL, NULL);
    return (CdbLen8 != 0) ? CdbLen8 : CdbLen32;
}

FORCEINLINE VOID
SrbGetPnpInfo(_In_ PVOID Srb, ULONG* PnPFlags, ULONG* PnPAction) {
    PSCSI_PNP_REQUEST_BLOCK pPnpSrb = NULL;
    PSRBEX_DATA_PNP pSrbExPnp = NULL;
    pSrbExPnp = (PSRBEX_DATA_PNP)SrbGetSrbExDataByType(
        (PSTORAGE_REQUEST_BLOCK)Srb, SrbExDataTypePnP);
    if (pSrbExPnp != NULL) {
        *PnPFlags = pSrbExPnp->SrbPnPFlags;
        *PnPAction = pSrbExPnp->PnPAction;
    }
    else {
        pPnpSrb = (PSCSI_PNP_REQUEST_BLOCK)Srb;
        *PnPFlags = pPnpSrb->SrbPnPFlags;
        *PnPAction = pPnpSrb->PnPAction;
    }
}

#define PSRB_TYPE PSTORAGE_REQUEST_BLOCK
#define PSRB_WMI_DATA PSRBEX_DATA_WMI
#define PSTOR_DEVICE_CAPABILITIES_TYPE PSTOR_DEVICE_CAPABILITIES_EX
#define SRB_EXTENSION(Srb) SrbGetMiniportContext(Srb)
#define SRB_FUNCTION(Srb) SrbGetSrbFunction(Srb)
#define SRB_CDB(Srb) SrbGetCdb(Srb)
#define SRB_CDB_LENGTH(Srb) SrbGetCdbLenght(Srb)
#define SRB_FLAGS(Srb) SrbGetSrbFlags(Srb)
#define SRB_PATH_ID(Srb) SrbGetPathId(Srb)
#define SRB_TARGET_ID(Srb) SrbGetTargetId(Srb)
#define SRB_LUN(Srb) SrbGetLun(Srb)
#define SRB_DATA_BUFFER(Srb) SrbGetDataBuffer(Srb)
#define SRB_DATA_TRANSFER_LENGTH(Srb) SrbGetDataTransferLength(Srb)
#define SRB_LENGTH(Srb) SrbGetSrbLength(Srb)
#define SRB_WMI_DATA(Srb) (PSRBEX_DATA_WMI)SrbGetSrbExDataByType((PSTORAGE_REQUEST_BLOCK)Srb, SrbExDataTypeWmi)
#define SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLen) SrbGetScsiData(Srb, NULL, NULL, NULL, &senseInfoBuffer, &senseInfoBufferLen)
#define SRB_GET_SENSE_INFO_BUFFER(Srb, senseInfoBuffer) SrbGetScsiData(Srb, NULL, NULL, NULL, &senseInfoBuffer, NULL)
#define SRB_GET_PNP_INFO(Srb, PnPFlags, PnPAction) SrbGetPnpInfo(Srb, &PnPFlags, &PnPAction)
#define SRB_SET_SCSI_STATUS(Srb, status) SrbSetScsiData(Srb, NULL, NULL, &status, NULL, NULL)
#define SRB_SET_SRB_STATUS(Srb, status) SrbSetSrbStatus(Srb, status)
#define SRB_SET_DATA_TRANSFER_LENGTH(Srb, Len) SrbSetDataTransferLength(Srb, Len)
#else
#define PSRB_TYPE PSCSI_REQUEST_BLOCK
#define PSRB_WMI_DATA PSCSI_WMI_REQUEST_BLOCK
#define PSTOR_DEVICE_CAPABILITIES_TYPE PSTOR_DEVICE_CAPABILITIES
#define SRB_EXTENSION(Srb) (PSRB_EXTENSION)Srb->SrbExtension
#define SRB_FUNCTION(Srb) Srb->Function
#define SRB_CDB(Srb) (PCDB)&Srb->Cdb[0]
#define SRB_CDB_LENGTH(Srb) Srb->CdbLength
#define SRB_FLAGS(Srb) Srb->SrbFlags
#define SRB_PATH_ID(Srb) Srb->PathId
#define SRB_TARGET_ID(Srb) Srb->TargetId
#define SRB_LUN(Srb) Srb->Lun
#define SRB_DATA_BUFFER(Srb) Srb->DataBuffer
#define SRB_DATA_TRANSFER_LENGTH(Srb) Srb->DataTransferLength
#define SRB_LENGTH(Srb) Srb->Lenght
#define SRB_WMI_DATA(Srb) (PSCSI_WMI_REQUEST_BLOCK)Srb
#define SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLen) senseInfoBuffer = Srb->SenseInfoBuffer;senseInfoBufferLen = Srb->SenseInfoBufferLength
#define SRB_GET_SENSE_INFO_BUFFER(Srb, senseInfoBuffer)  senseInfoBuffer = Srb->SenseInfoBuffer
#define SRB_GET_PNP_INFO(Srb, PnPFlags, PnPAction) PnPFlags = ((PSCSI_PNP_REQUEST_BLOCK)Srb)->SrbPnPFlags; PnPAction = ((PSCSI_PNP_REQUEST_BLOCK)Srb)->PnPAction
#define SRB_SET_SCSI_STATUS(Srb, status) Srb->ScsiStatus = status
#define SRB_SET_SRB_STATUS(Srb, status) Srb->SrbStatus = status
#define SRB_SET_DATA_TRANSFER_LENGTH(Srb, Len) Srb->DataTransferLength = Len
#endif

BOOLEAN
RhelDoReadWrite(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

BOOLEAN
RhelDoFlush(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN BOOLEAN sync
    );

VOID
RhelShutDown(
    IN PVOID DeviceExtension
    );

ULONGLONG
RhelGetLba(
    IN PVOID DeviceExtension,
    IN PCDB Cdb
    );

VOID
RhelGetSerialNumber(
    IN PVOID DeviceExtension
    );

VOID
RhelGetDiskGeometry(
    IN PVOID DeviceExtension
    );

extern VirtIOSystemOps VioStorSystemOps;

#endif ___VIOSTOR_HW_HELPER_H___
