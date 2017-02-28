/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: helper.c
 *
 * Author(s):
 * Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * This file contains various virtio queue related routines.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#include "helper.h"
#include "utils.h"

#if (INDIRECT_SUPPORTED == 1)
#define SET_VA_PA() { ULONG len; va = adaptExt->indirect ? srbExt->desc : NULL; \
                      pa = va ? StorPortGetPhysicalAddress(DeviceExtension, NULL, va, &len).QuadPart : 0; \
                    }
#else
#define SET_VA_PA()   va = NULL; pa = 0;
#endif

BOOLEAN
SendSRB(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va = NULL;
    ULONGLONG           pa = 0;
    ULONG               QueueNumber = 0;
    ULONG               MessageId = 0;
    BOOLEAN             result = FALSE;
    bool                notify = FALSE;
    STOR_LOCK_HANDLE    LockHandle = { 0 };
#ifdef ENABLE_WMI
    ULONGLONG           timeSinceLastStartIo;
    PVIRTQUEUE_STATISTICS queueStats;
#endif
ENTER_FN();
    SET_VA_PA();
    if (adaptExt->num_queues > 1) {
        QueueNumber = adaptExt->cpu_to_vq_map[srbExt->cpu] + VIRTIO_SCSI_REQUEST_QUEUE_0;
    }
    else {
        QueueNumber = VIRTIO_SCSI_REQUEST_QUEUE_0;
    }
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_IO, "SrbInfo", "issued on", srbExt->cpu,
        "QueueNumber", QueueNumber);

    MessageId = QueueNumber + 1;
#ifdef ENABLE_WMI
    queueStats = &adaptExt->QueueStats[QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0];
    srbExt->startTsc = ReadTimeStampCounter();
#endif
    VioScsiVQLock(DeviceExtension, MessageId, &LockHandle, FALSE);
#ifdef ENABLE_WMI
    if (queueStats->LastStartIo != 0) {
        timeSinceLastStartIo = srbExt->startTsc - queueStats->LastStartIo;
        if (queueStats->MaxStartIoDelay < timeSinceLastStartIo) {
            queueStats->MaxStartIoDelay = timeSinceLastStartIo;
        }
    }
    queueStats->LastStartIo = srbExt->startTsc;
#endif
    if (virtqueue_add_buf(adaptExt->vq[QueueNumber],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
#ifdef ENABLE_WMI
        queueStats->TotalRequests++;
        adaptExt->TargetStats[SRB_TARGET_ID(Srb)].TotalRequests++;
#endif
        result = TRUE;
        notify = virtqueue_kick_prepare(adaptExt->vq[QueueNumber]);
    }
    else {
#ifdef ENABLE_WMI
        queueStats->QueueFullEvents++;
#endif
        TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Cant add packet to queue", "QueueNumber", QueueNumber);
    }
#ifndef USE_WORK_ITEM

    if (CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {


        ProcessQueue(DeviceExtension, MessageId, TRUE);


    }

#endif
    VioScsiVQUnlock(DeviceExtension, MessageId, &LockHandle, FALSE);
    if (notify) {
        virtqueue_notify(adaptExt->vq[QueueNumber]);
#ifdef ENABLE_WMI
        queueStats->TotalKicks++;
#endif
    }
    else {
#ifdef ENABLE_WMI
        queueStats->SkippedKicks++;
#endif
    }
#ifdef USE_WORK_ITEM
#if (NTDDI_VERSION > NTDDI_WIN7)
    if (adaptExt->num_queues > 1) {
        if (CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {
            ULONG msg = MessageId - 3;
            PSTOR_SLIST_ENTRY   listEntryRev, listEntry;
            ULONG status = StorPortInterlockedFlushSList(DeviceExtension, &adaptExt->srb_list[msg], &listEntryRev);
            if ((status == STOR_STATUS_SUCCESS) && (listEntryRev != NULL)) {
                listEntry = listEntryRev;
                while(listEntry)
                {
                    PVirtIOSCSICmd  cmd = NULL;
                    PSTOR_SLIST_ENTRY next = listEntry->Next;
                    srbExt = CONTAINING_RECORD(listEntry,
                                SRB_EXTENSION, list_entry);

                    ASSERT(srbExt);
                    cmd = (PVirtIOSCSICmd)srbExt->priv;
                    ASSERT(cmd);
                    HandleResponse(DeviceExtension, cmd, QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0);
                    listEntry = next;
                }
            }
        }
    }
#endif
#endif
    return result;
EXIT_FN();
}

BOOLEAN
SynchronizedTMFRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK Srb      = (PSCSI_REQUEST_BLOCK) Context;
    PSRB_EXTENSION      srbExt   = (PSRB_EXTENSION)Srb->SrbExtension;
    PVOID               va;
    ULONGLONG           pa;

ENTER_FN();
    SET_VA_PA();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE]);
        return TRUE;
    }
    Srb->SrbStatus = SRB_STATUS_BUSY;
    StorPortBusy(DeviceExtension, adaptExt->queue_depth);
EXIT_ERR();
    return FALSE;
}

BOOLEAN
SendTMF(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
ENTER_FN();
    return StorPortSynchronizeAccess(DeviceExtension, SynchronizedTMFRoutine, (PVOID)Srb);
EXIT_FN();
}

BOOLEAN
SynchronizedVssControlRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE           Srb      = (PSRB_TYPE)Context;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va;
    ULONGLONG           pa;

ENTER_FN();
    SET_VA_PA();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE]);
        return TRUE;
    }
    Srb->SrbStatus = SRB_STATUS_BUSY;
    StorPortBusy(DeviceExtension, adaptExt->queue_depth);
EXIT_ERR();
    return FALSE;
}

BOOLEAN
SendVssControl(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
ENTER_FN();
    return StorPortSynchronizeAccess(DeviceExtension,
                                     SynchronizedVssControlRoutine,
                                     (PVOID)Srb);
EXIT_FN();
}

BOOLEAN
DeviceReset(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK   Srb = &adaptExt->tmf_cmd.Srb;
    PSRB_EXTENSION        srbExt = adaptExt->tmf_cmd.SrbExtension;
    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

ENTER_FN();
    if (adaptExt->dump_mode) {
        return TRUE;
    }
    ASSERT(adaptExt->tmf_infly == FALSE);
    Srb->SrbExtension = srbExt;
    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->srb = (PVOID)Srb;
    cmd->req.tmf.lun[0] = 1;
    cmd->req.tmf.lun[1] = 0;
    cmd->req.tmf.lun[2] = 0;
    cmd->req.tmf.lun[3] = 0;
    cmd->req.tmf.type = VIRTIO_SCSI_T_TMF;
    cmd->req.tmf.subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length   = sizeof(cmd->req.tmf);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.tmf);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;
    StorPortPause(DeviceExtension, 60);
    if (!SendTMF(DeviceExtension, Srb)) {
        StorPortResume(DeviceExtension);
        return FALSE;
    }
    adaptExt->tmf_infly = TRUE;
    return TRUE;
}

BOOLEAN
ReportDriverVersion(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK   Srb = &adaptExt->tmf_cmd.Srb;
    PSRB_EXTENSION        srbExt = adaptExt->tmf_cmd.SrbExtension;
    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

    ENTER_FN();
    if (adaptExt->dump_mode ||
        !CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION)) {
        return TRUE;
    }
    ASSERT(adaptExt->tmf_infly == FALSE);
    Srb->SrbExtension = srbExt;
    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->srb = (PVOID)Srb;
    cmd->req.google.lun[0] = 1;
    cmd->req.google.lun[1] = 0;
    cmd->req.google.lun[2] = 0;
    cmd->req.google.lun[3] = 0;
    cmd->req.google.type = VIRTIO_SCSI_T_GOOGLE;
    cmd->req.google.subtype = VIRTIO_SCSI_T_GOOGLE_REPORT_DRIVER_VERSION;
    cmd->req.google.data = _NT_TARGET_MIN;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->req.google);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.google);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;
    StorPortPause(DeviceExtension, 60);
    if (!SendTMF(DeviceExtension, Srb)) {
        StorPortResume(DeviceExtension);
        return FALSE;
    }
    adaptExt->tmf_infly = TRUE;
    return TRUE;
}

BOOLEAN
ReportSnapshotStatus(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN u64 Status
    )
{
    PSRB_TYPE  workingSrb = NULL;
    PSRB_EXTENSION srbExt = NULL;
    PADAPTER_EXTENSION    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN ignoreStorportSync = false;
    ENTER_FN();
    if (adaptExt->dump_mode) {
        return TRUE;
    }
    if (!Srb) {
        // If there is no Srb present, use the global structure in the device
        // extension to allow fast failure.
        workingSrb = (PSRB_TYPE) &adaptExt->snapshot_fail_srb;
        srbExt = &adaptExt->snapshot_fail_extension;

        srbExt->Srb = (PSCSI_REQUEST_BLOCK) workingSrb;
        ((PSCSI_REQUEST_BLOCK) workingSrb)->SrbExtension = srbExt;
        ignoreStorportSync = true;
    } else {
        workingSrb = Srb;
        srbExt = SRB_EXTENSION(workingSrb);
    }

    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->srb = workingSrb;
    cmd->req.google.lun[0] = 1;
    cmd->req.google.lun[1] = Target;
    cmd->req.google.lun[2] = 0;
    cmd->req.google.lun[3] = Lun;
    cmd->req.google.lun[4] = 0;
    cmd->req.google.lun[5] = 0;
    cmd->req.google.lun[6] = 0;
    cmd->req.google.lun[7] = 0;

    cmd->req.google.type = VIRTIO_SCSI_T_GOOGLE;
    cmd->req.google.subtype = VIRTIO_SCSI_T_GOOGLE_REPORT_SNAPSHOT_READY;
    cmd->req.google.data = Status;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr =
        StorPortGetPhysicalAddress(
            DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->req.google);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr =
        StorPortGetPhysicalAddress(
            DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.google);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;

    if (ignoreStorportSync) {
        return SynchronizedVssControlRoutine(DeviceExtension, workingSrb);
    }
    return SendVssControl(DeviceExtension, workingSrb);
}

VOID
ShutDown(
    IN PVOID DeviceExtension
    )
{
    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();
    virtio_device_reset(&adaptExt->vdev);
    virtio_delete_queues(&adaptExt->vdev);
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        if (adaptExt->vq[index]) {
            if (adaptExt->dump_mode && adaptExt->original_queue_num[index] != 0) {
                 virtio_set_queue_allocation(&adaptExt->vdev, index, adaptExt->original_queue_num[index]);
            }
            adaptExt->vq[index] = NULL;
        }
        adaptExt->vq[index] = NULL;
    }

    virtio_device_shutdown(&adaptExt->vdev);
EXIT_FN();
}

VOID
GetScsiConfig(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TRACE_CONTEXT_NO_SRB();

ENTER_FN();

    adaptExt->features = virtio_get_features(&adaptExt->vdev);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, seg_max),
                      &adaptExt->scsi_config.seg_max, sizeof(adaptExt->scsi_config.seg_max));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "seg_max", adaptExt->scsi_config.seg_max);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, num_queues),
                      &adaptExt->scsi_config.num_queues, sizeof(adaptExt->scsi_config.num_queues));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "num_queues", adaptExt->scsi_config.num_queues);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_sectors),
                      &adaptExt->scsi_config.max_sectors, sizeof(adaptExt->scsi_config.max_sectors));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "max_sectors", adaptExt->scsi_config.max_sectors);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, cmd_per_lun),
                      &adaptExt->scsi_config.cmd_per_lun, sizeof(adaptExt->scsi_config.cmd_per_lun));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "cmd_per_lun", adaptExt->scsi_config.cmd_per_lun);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, event_info_size),
                      &adaptExt->scsi_config.event_info_size, sizeof(adaptExt->scsi_config.event_info_size));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "event_info_size", adaptExt->scsi_config.event_info_size);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, sense_size),
                      &adaptExt->scsi_config.sense_size, sizeof(adaptExt->scsi_config.sense_size));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "sense_size", adaptExt->scsi_config.sense_size);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, cdb_size),
                      &adaptExt->scsi_config.cdb_size, sizeof(adaptExt->scsi_config.cdb_size));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "cdb_size", adaptExt->scsi_config.cdb_size);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_channel),
                      &adaptExt->scsi_config.max_channel, sizeof(adaptExt->scsi_config.max_channel));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "max_channel", adaptExt->scsi_config.max_channel);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_target),
                      &adaptExt->scsi_config.max_target, sizeof(adaptExt->scsi_config.max_target));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "max_target", adaptExt->scsi_config.max_target);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_lun),
                      &adaptExt->scsi_config.max_lun, sizeof(adaptExt->scsi_config.max_lun));
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Adapter config", "max_lun", adaptExt->scsi_config.max_lun);

EXIT_FN();
}

BOOLEAN
InitVirtIODevice(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    NTSTATUS status;
    TRACE_CONTEXT_NO_SRB();

    status = virtio_device_initialize(
        &adaptExt->vdev,
        &VioScsiSystemOps,
        adaptExt,
        adaptExt->msix_enabled);
    if (!NT_SUCCESS(status)) {
        LogError(adaptExt,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Failed to initialize virtio device", "error", status);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
InitHW(
    IN PVOID DeviceExtension,
    IN PPORT_CONFIGURATION_INFORMATION ConfigInfo
    )
{
    PACCESS_RANGE      accessRange;
    PADAPTER_EXTENSION adaptExt;
    ULONG pci_cfg_len, i;
    TRACE_CONTEXT_NO_SRB();

ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    adaptExt->system_io_bus_number = ConfigInfo->SystemIoBusNumber;

    /* read PCI config space */
    pci_cfg_len = StorPortGetBusData(
        DeviceExtension,
        PCIConfiguration,
        ConfigInfo->SystemIoBusNumber,
        (ULONG)ConfigInfo->SlotNumber,
        (PVOID)&adaptExt->pci_config_buf,
        sizeof(adaptExt->pci_config_buf));

    if (pci_cfg_len != sizeof(adaptExt->pci_config_buf)) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot read pci configuration space", "pci_cfg_len", pci_cfg_len);
        return FALSE;
    }

#if (MSI_SUPPORTED == 1)
    {
        UCHAR CapOffset;
        PPCI_MSIX_CAPABILITY pMsixCapOffset;
        PPCI_COMMON_HEADER   pPciComHeader;
        pPciComHeader = &adaptExt->pci_config;
        if ((pPciComHeader->Status & PCI_STATUS_CAPABILITIES_LIST) == 0)
        {
            TRACE(TRACE_LEVEL_INFORMATION, DRIVER_START, "No capabilities list");
        } else
        {
            if ((pPciComHeader->HeaderType & (~PCI_MULTIFUNCTION)) == PCI_DEVICE_TYPE)
            {
                CapOffset = pPciComHeader->u.type0.CapabilitiesPtr;
                while (CapOffset != 0)
                {
                    pMsixCapOffset = (PPCI_MSIX_CAPABILITY)&adaptExt->pci_config_buf[CapOffset];
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_MSIX)
                    {
                        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "TableSize", pMsixCapOffset->MessageControl.TableSize);
                        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "FunctionMask", pMsixCapOffset->MessageControl.FunctionMask);
                        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "MSIXEnable", pMsixCapOffset->MessageControl.MSIXEnable);

                        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageTable", "Value", *((ULONGLONG*)&pMsixCapOffset->MessageTable));
                        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "PBATable", "Value", *((ULONGLONG*)&pMsixCapOffset->PBATable));
                        adaptExt->msix_enabled = (pMsixCapOffset->MessageControl.MSIXEnable == 1);
                    } else
                    {
                        TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Capability enum", "CapabilityID", pMsixCapOffset->Header.CapabilityID, "Next CapOffset", CapOffset);
                    }
                    CapOffset = pMsixCapOffset->Header.Next;
                }
                TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "msix_enabled", "Value", adaptExt->msix_enabled);
            } else
            {
                TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "NOT A PCI_DEVICE_TYPE");
            }
        }
    }
#endif

    /* initialize the pci_bars array */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++) {
        accessRange = *ConfigInfo->AccessRanges + i;
        if (accessRange->RangeLength != 0) {
            int iBar = virtio_get_bar_index(&adaptExt->pci_config, accessRange->RangeStart);
            if (iBar == -1) {
               TRACE1(TRACE_LEVEL_FATAL, DRIVER_START,
                      "Cannot get index for BAR", "bar", accessRange->RangeStart.QuadPart);
                return FALSE;
            }
            adaptExt->pci_bars[iBar].BasePA = accessRange->RangeStart;
            adaptExt->pci_bars[iBar].uLength = accessRange->RangeLength;
            adaptExt->pci_bars[iBar].bPortSpace = !accessRange->RangeInMemory;
        }
    }

    /* initialize the virtual device */
    if (!InitVirtIODevice(DeviceExtension)) {
        return FALSE;
    }

EXIT_FN();
    return TRUE;
}

BOOLEAN
SynchronizedKickEventRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVirtIOSCSIEventNode eventNode   = (PVirtIOSCSIEventNode) Context;
    PVOID               va = NULL;
    ULONGLONG           pa = 0;

ENTER_FN();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE],
                     &eventNode->sg,
                     0, 1,
                     eventNode, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE]);
        return TRUE;
    }
EXIT_ERR();
    return FALSE;
}


BOOLEAN
KickEvent(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEventNode EventNode
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG              fragLen;

ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    memset((PVOID)EventNode, 0, sizeof(VirtIOSCSIEventNode));
    EventNode->sg.physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &EventNode->event, &fragLen);
    EventNode->sg.length   = sizeof(VirtIOSCSIEvent);
    return SynchronizedKickEventRoutine(DeviceExtension, (PVOID)EventNode);
EXIT_FN();
}

VOID
//FORCEINLINE
VioScsiVQLock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN OUT PSTOR_LOCK_HANDLE LockHandle,
    IN BOOLEAN isr
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TRACE_CONTEXT_NO_SRB();
ENTER_FN();
    if (!isr) {
        if (adaptExt->msix_enabled) {
            // Queue numbers start at 0, message ids at 1.
            NT_ASSERT(MessageID > VIRTIO_SCSI_REQUEST_QUEUE_0);
            NT_ASSERT(MessageID <= VIRTIO_SCSI_REQUEST_QUEUE_0 + adaptExt->num_queues);
            StorPortAcquireSpinLock(DeviceExtension, DpcLock, &adaptExt->dpc[MessageID - VIRTIO_SCSI_REQUEST_QUEUE_0 - 1], LockHandle);
        }
        else {
            StorPortAcquireSpinLock(DeviceExtension, InterruptLock, NULL, LockHandle);
        }
    }
EXIT_FN();
}

VOID
//FORCEINLINE
VioScsiVQUnlock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN PSTOR_LOCK_HANDLE LockHandle,
    IN BOOLEAN isr
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TRACE_CONTEXT_NO_SRB();
ENTER_FN();
    if (!isr) {
        StorPortReleaseSpinLock(DeviceExtension, LockHandle);
    }
EXIT_FN();
}
