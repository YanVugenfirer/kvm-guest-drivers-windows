/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: vioscsi.c
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * This file contains vioscsi StorPort miniport driver
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#include "ntstatus.h"
#include "helper.h"
#include "snapshot.h"
#include "utils.h"
#include "vioscsi.h"
#include "resources.h"

BOOLEAN IsCrashDumpMode;

#if (NTDDI_VERSION > NTDDI_WIN7)
sp_DRIVER_INITIALIZE DriverEntry;
HW_INITIALIZE        VioScsiHwInitialize;
HW_BUILDIO           VioScsiBuildIo;
HW_STARTIO           VioScsiStartIo;
HW_FIND_ADAPTER      VioScsiFindAdapter;
HW_RESET_BUS         VioScsiResetBus;
HW_ADAPTER_CONTROL   VioScsiAdapterControl;
HW_INTERRUPT         VioScsiInterrupt;
HW_DPC_ROUTINE       VioScsiCompleteDpcRoutine;
HW_PASSIVE_INITIALIZE_ROUTINE         VioScsiIoPassiveInitializeRoutine;
HW_WORKITEM          VioScsiWorkItemCallback;
#if (MSI_SUPPORTED == 1)
HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE VioScsiMSInterrupt;
#endif
#endif

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    );

BOOLEAN
VioScsiHwReinitialize(
    IN PVOID DeviceExtension
    );

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    );

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    );

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    );

NTSTATUS
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
CompleteRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID
    );

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    );

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
CompleteSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    BOOLEAN DeviceAck
    );

VOID
CompleteSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN ULONG ReturnCode
    );

VOID
RequestSnapshot(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
ProcessSnapshotCompletion(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

#if (MSI_SUPPORTED == 1)
BOOLEAN
VioScsiMSInterrupt(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageID
    );
#endif


NTSTATUS
VioScsiIoControl(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

VOID
VioScsiSaveInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    );

BOOLEAN
SetSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN PSRB_TYPE Srb
    )
{
    PSRB_TYPE current = InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_requested), Srb, NULL);
    if (current == NULL)
        return TRUE;
    else
        return FALSE;
}

PSRB_TYPE
ClearSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt
    )
{
    PSRB_TYPE current = (PSRB_TYPE)adaptExt->srb_snapshot_requested;
    return (PSRB_TYPE)InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_requested), NULL, current);
}

BOOLEAN
SetSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN PSRB_TYPE Srb
    )
{
    PSRB_TYPE current = InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_can_proceeed), Srb, NULL);
    if (current == NULL)
        return TRUE;
    else
        return FALSE;
}

PSRB_TYPE
ClearSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt
    )
{
    PSRB_TYPE current = (PSRB_TYPE)adaptExt->srb_snapshot_can_proceeed;
    return (PSRB_TYPE)InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_can_proceeed), NULL, current);
}

ULONG
DriverEntry(
    IN PVOID  DriverObject,
    IN PVOID  RegistryPath
    )
{

    HW_INITIALIZATION_DATA hwInitData;
    ULONG                  initResult;
    TRACE_CONTEXT_NO_DEVICE_EXTENSION();

    InitializeDriverOptions((PDRIVER_OBJECT)DriverObject, (PUNICODE_STRING)RegistryPath);

    TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "Vioscsi driver started", "build", _NT_TARGET_MIN);
    IsCrashDumpMode = FALSE;
    if (RegistryPath == NULL) {
        TRACE(TRACE_LEVEL_WARNING, DRIVER_START, "DriverEntry: Crash dump mode");
        IsCrashDumpMode = TRUE;
    }

    memset(&hwInitData, 0, sizeof(HW_INITIALIZATION_DATA));

    hwInitData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);

    hwInitData.HwFindAdapter            = VioScsiFindAdapter;
    hwInitData.HwInitialize             = VioScsiHwInitialize;
    hwInitData.HwStartIo                = VioScsiStartIo;
    hwInitData.HwInterrupt              = VioScsiInterrupt;
    hwInitData.HwResetBus               = VioScsiResetBus;
    hwInitData.HwAdapterControl         = VioScsiAdapterControl;
    hwInitData.HwBuildIo                = VioScsiBuildIo;
    hwInitData.NeedPhysicalAddresses    = TRUE;
    hwInitData.TaggedQueuing            = TRUE;
    hwInitData.AutoRequestSense         = TRUE;
    hwInitData.MultipleRequestPerLu     = TRUE;

    hwInitData.DeviceExtensionSize      = sizeof(ADAPTER_EXTENSION);
    hwInitData.SrbExtensionSize         = sizeof(SRB_EXTENSION);

    hwInitData.AdapterInterfaceType     = PCIBus;

    /* Virtio doesn't specify the number of BARs used by the device; it may
     * be one, it may be more. PCI_TYPE0_ADDRESSES, the theoretical maximum
     * on PCI, is a safe upper bound.
     */
    hwInitData.NumberOfAccessRanges     = PCI_TYPE0_ADDRESSES;
    hwInitData.MapBuffers               = STOR_MAP_NON_READ_WRITE_BUFFERS;

#if (NTDDI_VERSION > NTDDI_WIN7)
    /* Specify support/use SRB Extension for Windows 8 and up */
    hwInitData.SrbTypeFlags = SRB_TYPE_FLAG_STORAGE_REQUEST_BLOCK;
    hwInitData.FeatureSupport = STOR_FEATURE_FULL_PNP_DEVICE_CAPABILITIES;
#endif

    initResult = StorPortInitialize(DriverObject,
                                    RegistryPath,
                                    &hwInitData,
                                    NULL);

    TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_START, "Initialize returned", "Result", initResult);

    return initResult;

}

#ifdef ENABLE_WMI
ULONG PortNumber = 0;
#endif

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    )
{
    PADAPTER_EXTENSION adaptExt;
    PVOID              uncachedExtensionVa;
    USHORT             queueLength = 0;
    ULONG              Size;
    ULONG              HeapSize;
    ULONG              extensionSize;
    ULONG              index;
    ULONG              num_cpus;
    ULONG              max_cpus;
    ULONG              max_queues;
    TRACE_CONTEXT_NO_SRB();

    UNREFERENCED_PARAMETER( HwContext );
    UNREFERENCED_PARAMETER( BusInformation );
    UNREFERENCED_PARAMETER( ArgumentString );
    UNREFERENCED_PARAMETER( Again );

ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    memset(adaptExt, 0, sizeof(ADAPTER_EXTENSION));

    adaptExt->dump_mode  = IsCrashDumpMode;
    adaptExt->hba_id     = HBA_ID;
    ConfigInfo->Master                      = TRUE;
    ConfigInfo->ScatterGather               = TRUE;
    ConfigInfo->Dma32BitAddresses           = TRUE;
#if (NTDDI_VERSION > NTDDI_WIN7)
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_FULL64BIT_SUPPORTED;
#else
    ConfigInfo->Dma64BitAddresses = TRUE;
#endif
    ConfigInfo->AlignmentMask = 0x3;
    ConfigInfo->MapBuffers                  = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->SynchronizationModel        = StorSynchronizeFullDuplex;
#if (MSI_SUPPORTED == 1)
    ConfigInfo->HwMSInterruptRoutine        = VioScsiMSInterrupt;
    ConfigInfo->InterruptSynchronizationMode=InterruptSynchronizePerMessage;
#endif
#ifdef ENABLE_WMI
    ConfigInfo->WmiDataProvider = TRUE;
    WmiInitializeContext(adaptExt);
#if (NTDDI_VERSION <= NTDDI_WIN7)
    adaptExt->PortNumber = (USHORT) InterlockedIncrement(&PortNumber);
#endif
#else
    ConfigInfo->WmiDataProvider = FALSE;
#endif
    if (!InitHW(DeviceExtension, ConfigInfo)) {
        TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot initialize HardWare");
        return SP_RETURN_NOT_FOUND;
    }

    GetScsiConfig(DeviceExtension);

    ConfigInfo->NumberOfBuses               = 1;
    ConfigInfo->MaximumNumberOfTargets      = min((UCHAR)adaptExt->scsi_config.max_target, 255/*SCSI_MAXIMUM_TARGETS_PER_BUS*/);
    ConfigInfo->MaximumNumberOfLogicalUnits = min((UCHAR)adaptExt->scsi_config.max_lun, SCSI_MAXIMUM_LUNS_PER_TARGET);
    if(adaptExt->dump_mode) {
        ConfigInfo->NumberOfPhysicalBreaks  = 8;
    } else {
        ConfigInfo->NumberOfPhysicalBreaks  = min((MAX_PHYS_SEGMENTS + 1), adaptExt->scsi_config.seg_max);
    }
    ConfigInfo->MaximumTransferLength       = 0x00FFFFFF;

#if (NTDDI_VERSION >= NTDDI_WIN7)
    num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    max_cpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
#elif (NTDDI_VERSION >= NTDDI_VISTA)
    num_cpus = KeQueryActiveProcessorCount(NULL);
    max_cpus = KeQueryMaximumProcessorCount();
#else
    num_cpus = max_cpus = KeNumberProcessors;
#endif
    adaptExt->num_queues = adaptExt->scsi_config.num_queues;

    if (adaptExt->dump_mode || !adaptExt->msix_enabled)
    {
        adaptExt->num_queues = 1;
    }
    if (adaptExt->num_queues > 1) {
        for (index = 0; index < num_cpus; index++) {
            adaptExt->cpu_to_vq_map[index] = (UCHAR)(index % adaptExt->num_queues);
        }
    } else {
        memset(adaptExt->cpu_to_vq_map, 0, MAX_CPU);
    }

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Multiqueue", "Queue", adaptExt->num_queues, "CPUs", num_cpus);

    /* Figure out the maximum number of queues we will ever need to set up. Note that this may
     * be higher than adaptExt->num_queues, because the driver may be reinitialized by calling
     * VioScsiFindAdapter again with more CPUs enabled. Unfortunately StorPortGetUncachedExtension
     * only allocates when called for the first time so we need to always use this upper bound.
     */
    max_queues = min(max_cpus, adaptExt->scsi_config.num_queues);
    if (adaptExt->num_queues > max_queues) {
        TRACE(TRACE_LEVEL_WARNING, DRIVER_START, "Multiqueue can only use at most one queue per cpu.");
        adaptExt->num_queues = max_queues;
    }

    /* This function is our only chance to allocate memory for the driver; allocations are not
     * possible later on. Even worse, the only allocation mechanism guaranteed to work in all
     * cases is StorPortGetUncachedExtension, which gives us one block of physically contiguous
     * pages.
     *
     * Allocations that need to be page-aligned will be satisfied from this one block starting
     * at the first page-aligned offset, up to adaptExt->pageAllocationSize computed below. Other
     * allocations will be cache-line-aligned, of total size adaptExt->poolAllocationSize, also
     * computed below.
     */
    adaptExt->pageAllocationSize = 0;
    adaptExt->poolAllocationSize = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;
    Size = 0;
    #define MAX_DUMP_MODE_QUEUE_NUM 256
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        virtio_query_queue_allocation(&adaptExt->vdev, index, &queueLength, &Size, &HeapSize);
        if (Size == 0) {
            LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Virtual queue config failed", "queue", index);
            return SP_RETURN_ERROR;
        }
        if (adaptExt->dump_mode && queueLength > MAX_DUMP_MODE_QUEUE_NUM) {
           adaptExt->original_queue_num[index] = queueLength;
           virtio_set_queue_allocation(&adaptExt->vdev, index, MAX_DUMP_MODE_QUEUE_NUM);
           virtio_query_queue_allocation(&adaptExt->vdev, index, &queueLength, &Size, &HeapSize);
        }

        adaptExt->pageAllocationSize += ROUND_TO_PAGES(Size);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(HeapSize);
    }
    if (!adaptExt->dump_mode) {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(SRB_EXTENSION));
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(VirtIOSCSIEventNode) * 8);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(STOR_DPC) * max_queues);
    }
    if (max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 > MAX_QUEUES_PER_DEVICE_DEFAULT)
    {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(
            (max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0) * virtio_get_queue_descriptor_size());
    }

#if (INDIRECT_SUPPORTED == 1)
    if(!adaptExt->dump_mode) {
        adaptExt->indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);
    }
#else
    adaptExt->indirect = 0;
#endif

    if(adaptExt->indirect) {
        adaptExt->queue_depth = max(20, (queueLength / 4));
    } else {
        // Each message uses one virtqueue descriptor for the scsi command, one descriptor
        // for scsi response and up to ConfigInfo->NumberOfPhysicalBreaks for the data.
        adaptExt->queue_depth = queueLength / (ConfigInfo->NumberOfPhysicalBreaks + 2) - 1;
    }
#if (NTDDI_VERSION > NTDDI_WIN7)
    ConfigInfo->MaxIOsPerLun = adaptExt->queue_depth * adaptExt->num_queues;
    ConfigInfo->InitialLunQueueDepth = ConfigInfo->MaxIOsPerLun;
    if (ConfigInfo->MaxIOsPerLun * ConfigInfo->MaximumNumberOfTargets > ConfigInfo->MaxNumberOfIO) {
        ConfigInfo->MaxNumberOfIO = ConfigInfo->MaxIOsPerLun * ConfigInfo->MaximumNumberOfTargets;
    }
#else
    // Prior to win8, lun queue depth must be at most 254.
    adaptExt->queue_depth = min(254, adaptExt->queue_depth);
#endif

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "ConfigInfo", "NumberOfPhysicalBreaks", ConfigInfo->NumberOfPhysicalBreaks, "QueueDepth", adaptExt->queue_depth);

    extensionSize = PAGE_SIZE + adaptExt->pageAllocationSize + adaptExt->poolAllocationSize;
    uncachedExtensionVa = StorPortGetUncachedExtension(DeviceExtension, ConfigInfo, extensionSize);
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StorPortGetUncachedExtension", "uncachedExtensionVa", uncachedExtensionVa, "size", extensionSize);
    if (!uncachedExtensionVa) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Can't get uncached extension", "size", extensionSize);
        return SP_RETURN_ERROR;
    }

    /* At this point we have all the memory we're going to need. We lay it out as follows.
     * Note that StorPortGetUncachedExtension tends to return page-aligned memory so the
     * padding1 region will typically be empty and the size of padding2 equal to PAGE_SIZE.
     *
     * uncachedExtensionVa    pageAllocationVa         poolAllocationVa
     * +----------------------+------------------------+--------------------------+----------------------+
     * | \ \ \ \ \ \ \ \ \ \  |<= pageAllocationSize =>|<=  poolAllocationSize  =>| \ \ \ \ \ \ \ \ \ \  |
     * |  \ \  padding1 \ \ \ |                        |                          |  \ \  padding2 \ \ \ |
     * | \ \ \ \ \ \ \ \ \ \  |    page-aligned area   | pool area for cache-line | \ \ \ \ \ \ \ \ \ \  |
     * |  \ \ \ \ \ \ \ \ \ \ |                        | aligned allocations      |  \ \ \ \ \ \ \ \ \ \ |
     * +----------------------+------------------------+--------------------------+----------------------+
     * |<=====================================  extensionSize  =========================================>|
     */
    adaptExt->pageAllocationVa = (PVOID)(((ULONG_PTR)(uncachedExtensionVa) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    if (adaptExt->poolAllocationSize > 0) {
        adaptExt->poolAllocationVa = (PVOID)((ULONG_PTR)uncachedExtensionVa + adaptExt->pageAllocationSize);
    }
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Page-aligned area", "p", adaptExt->pageAllocationVa, "size", adaptExt->pageAllocationSize);
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Pool area", "p", adaptExt->poolAllocationVa, "size", adaptExt->poolAllocationSize);

#if (NTDDI_VERSION > NTDDI_WIN7)
    TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "Message affinity", "p", adaptExt->pmsg_affinity);
    if (!adaptExt->dump_mode && (adaptExt->num_queues > 1) && (adaptExt->pmsg_affinity == NULL)) {
        ULONG Status =
        StorPortAllocatePool(DeviceExtension,
                             sizeof(GROUP_AFFINITY) * (adaptExt->num_queues + 3),
                             VIOSCSI_POOL_TAG,
                             (PVOID*)&adaptExt->pmsg_affinity);
        TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Message affinity", "p", adaptExt->pmsg_affinity, "Status", Status);
    }
#endif

EXIT_FN();
    return SP_RETURN_FOUND;
}

BOOLEAN
VioScsiPassiveInitializeRoutine(
    IN PVOID DeviceExtension
    )
{
    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();
    for (index = 0; index < adaptExt->num_queues; ++index) {
        StorPortInitializeDpc(DeviceExtension,
            &adaptExt->dpc[index],
            VioScsiCompleteDpcRoutine);
    }
    adaptExt->dpc_ok = TRUE;
    ReportDriverVersion(DeviceExtension);
EXIT_FN();
    return TRUE;
}

static BOOLEAN InitializeVirtualQueues(PADAPTER_EXTENSION adaptExt, ULONG numQueues)
{
    ULONG index;
    NTSTATUS status;
    BOOLEAN useEventIndex = CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX);
    PVOID DeviceExtension = adaptExt;
    TRACE_CONTEXT_NO_SRB();

    status = virtio_find_queues(
        &adaptExt->vdev,
        numQueues,
        adaptExt->vq);
    if (!NT_SUCCESS(status)) {
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Virtio_find_queues failed", "error", status);
        return FALSE;
    }

    for (index = 0; index < numQueues; index++) {
        virtio_set_queue_event_suppression(
            adaptExt->vq[index],
            useEventIndex);
    }
    return TRUE;
}

PVOID
VioScsiPoolAlloc(
    IN PVOID DeviceExtension,
    IN SIZE_T size
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVOID ptr = (PVOID)((ULONG_PTR)adaptExt->poolAllocationVa + adaptExt->poolOffset);
    TRACE_CONTEXT_NO_SRB();

    if ((adaptExt->poolOffset + size) <= adaptExt->poolAllocationSize) {
        size = ROUND_TO_CACHE_LINES(size);
        adaptExt->poolOffset += (ULONG)size;
        RtlZeroMemory(ptr, size);
        return ptr;
    } else {
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Ran out of memory in VioScsiPoolAlloc", "size", size);
        return NULL;
    }
}

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG              i;
    ULONGLONG          guestFeatures = 0;

#if (MSI_SUPPORTED == 1)
    ULONG              index;
    PERF_CONFIGURATION_DATA perfData = { 0 };
    ULONG              status = STOR_STATUS_SUCCESS;
    MESSAGE_INTERRUPT_INFORMATION msi_info = { 0 };
#endif
    TRACE_CONTEXT_NO_SRB();

ENTER_FN();
    if (CHECKBIT(adaptExt->features, VIRTIO_F_VERSION_1)) {
        guestFeatures |= (1ULL << VIRTIO_F_VERSION_1);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_F_ANY_LAYOUT)) {
        guestFeatures |= (1ULL << VIRTIO_F_ANY_LAYOUT);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX)) {
        guestFeatures |= (1ULL << VIRTIO_RING_F_EVENT_IDX);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_CHANGE)) {
        guestFeatures |= (1ULL << VIRTIO_SCSI_F_CHANGE);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
        guestFeatures |= (1ULL << VIRTIO_SCSI_F_HOTPLUG);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_SNAPSHOT)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_GOOGLE_SNAPSHOT);
    }

    if (!NT_SUCCESS(virtio_set_features(&adaptExt->vdev, guestFeatures))) {
        TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Virtio_set_features failed");
        return FALSE;
    }

    adaptExt->msix_vectors = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;

#if (MSI_SUPPORTED == 1)
    while(StorPortGetMSIInfo(DeviceExtension, adaptExt->msix_vectors, &msi_info) == STOR_STATUS_SUCCESS) {
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageId", msi_info.MessageId);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageData", msi_info.MessageData);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptVector", msi_info.InterruptVector);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptLevel", msi_info.InterruptLevel);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptMode", msi_info.InterruptMode);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageAddress", msi_info.MessageAddress.QuadPart);
        ++adaptExt->msix_vectors;
    }

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StartInfo", "Queues", adaptExt->num_queues, "msix_vectors", adaptExt->msix_vectors);
    if (adaptExt->num_queues > 1 &&
        ((adaptExt->num_queues + 3) > adaptExt->msix_vectors)) {
        //FIXME
        adaptExt->num_queues = 1;
    }

    if (!adaptExt->dump_mode && adaptExt->msix_vectors > 0) {
        if (adaptExt->msix_vectors >= adaptExt->num_queues + 3) {
            /* initialize queues with a MSI vector per queue */
            TRACE(TRACE_LEVEL_INFORMATION, DRIVER_START, "Using a unique MSI vector per queue\n");
            adaptExt->msix_one_vector = FALSE;
        } else {
            /* if we don't have enough vectors, use one for all queues */
            TRACE(TRACE_LEVEL_INFORMATION, DRIVER_START, "Using one MSI vector for all queues\n");
            adaptExt->msix_one_vector = TRUE;
        }
        if (!InitializeVirtualQueues(adaptExt, adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0)) {
            return FALSE;
        }

        for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
              if ((adaptExt->num_queues > 1) &&
                  (index >= VIRTIO_SCSI_REQUEST_QUEUE_0)) {
                  if (!CHECKFLAG(adaptExt->perfFlags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                      adaptExt->cpu_to_vq_map[index - VIRTIO_SCSI_REQUEST_QUEUE_0] = (UCHAR)(index - VIRTIO_SCSI_REQUEST_QUEUE_0);
                  }
#if (NTDDI_VERSION > NTDDI_WIN7)
                  status = StorPortInitializeSListHead(DeviceExtension, &adaptExt->srb_list[index - VIRTIO_SCSI_REQUEST_QUEUE_0]);
                  if (status != STOR_STATUS_SUCCESS) {
                     TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "StorPortInitializeSListHead failed", "status", status);
                  }
#endif
              }
        }
    }
    else
#else
    adaptExt->num_queues = 1;
#endif
    {
        /* initialize queues with no MSI interrupts */
        adaptExt->msix_enabled = FALSE;
        if (!InitializeVirtualQueues(adaptExt, adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0)) {
            return FALSE;
        }
    }

    if (!adaptExt->dump_mode) {
        /* we don't get another chance to call StorPortEnablePassiveInitialization and initialize
         * DPCs if the adapter is being restarted, so leave our datastructures alone on restart
         */
        if (adaptExt->dpc == NULL) {
            adaptExt->tmf_cmd.SrbExtension = (PSRB_EXTENSION)VioScsiPoolAlloc(DeviceExtension, sizeof(SRB_EXTENSION));
            adaptExt->events = (PVirtIOSCSIEventNode)VioScsiPoolAlloc(DeviceExtension, sizeof(VirtIOSCSIEventNode) * 8);
            adaptExt->dpc = (PSTOR_DPC)VioScsiPoolAlloc(DeviceExtension, sizeof(STOR_DPC) * adaptExt->num_queues);
        }
    }

    if (!adaptExt->dump_mode && CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
        PVirtIOSCSIEventNode events = adaptExt->events;
        for (i = 0; i < 8; i++) {
           if (!KickEvent(DeviceExtension, (PVOID)(&events[i]))) {
               TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Can't add event", "index", i);
           }
        }
    }
    if (!adaptExt->dump_mode)
    {
#if (MSI_SUPPORTED == 1)
        if ((adaptExt->num_queues > 1) && (adaptExt->perfFlags == 0)) {
            perfData.Version = STOR_PERF_VERSION;
            perfData.Size = sizeof(PERF_CONFIGURATION_DATA);

            status = StorPortInitializePerfOpts(DeviceExtension, TRUE, &perfData);

            TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
            if (status == STOR_STATUS_SUCCESS) {
                perfData.Flags &= (~disabledPerfOptions);
                if (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION)) {
                    adaptExt->perfFlags |= STOR_PERF_DPC_REDIRECTION;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_CONCURRENT_CHANNELS)) {
                    adaptExt->perfFlags |= STOR_PERF_CONCURRENT_CHANNELS;
                    perfData.ConcurrentChannels = adaptExt->num_queues;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_INTERRUPT_MESSAGE_RANGES)) {
                    adaptExt->perfFlags |= STOR_PERF_INTERRUPT_MESSAGE_RANGES;
                    perfData.FirstRedirectionMessageNumber = 3;
                    perfData.LastRedirectionMessageNumber = perfData.FirstRedirectionMessageNumber + adaptExt->num_queues - 1;
                }
#if (NTDDI_VERSION > NTDDI_WIN7)
                if ((adaptExt->pmsg_affinity != NULL) && CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                    RtlZeroMemory((PCHAR)adaptExt->pmsg_affinity, sizeof (GROUP_AFFINITY)* (adaptExt->num_queues + 3));
                    adaptExt->perfFlags |= STOR_PERF_ADV_CONFIG_LOCALITY;
                    perfData.MessageTargets = adaptExt->pmsg_affinity;
                }
#endif
                if (CHECKFLAG(perfData.Flags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {
                    adaptExt->perfFlags |= STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO;
                }
                perfData.Flags = adaptExt->perfFlags;
                TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                    "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                    "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
                status = StorPortInitializePerfOpts(DeviceExtension, FALSE, &perfData);
                if (status != STOR_STATUS_SUCCESS) {
                    adaptExt->perfFlags = 0;
                    TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "StorPortInitializePerfOpts FALSE", "status", status);
                }
                else {
                    TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "Actual PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                        "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                        "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
#if (NTDDI_VERSION > NTDDI_WIN7)
                    if ((adaptExt->pmsg_affinity != NULL) && CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                        UCHAR msg = 0;
                        PGROUP_AFFINITY ga;
                        UCHAR cpu = 0;
                        for (msg = 0; msg < adaptExt->num_queues + 3; msg++) {
                            ga = &adaptExt->pmsg_affinity[msg];
                            if (ga->Mask > 0 && msg > 2) {
                                cpu = RtlFindLeastSignificantBit((ULONGLONG)ga->Mask);
                                adaptExt->cpu_to_vq_map[cpu] = msg - 3;
                                TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "Affinity", "msg", msg, "mask", ga->Mask, "group", ga->Group, "cpu", cpu, "vq", adaptExt->cpu_to_vq_map[cpu]);
                            }
                        }
                    }
#endif
                }
            }
            else {
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "StorPortInitializePerfOpts", "status", status);
            }
        }
#endif
        if (!adaptExt->dpc_ok && !StorPortEnablePassiveInitialization(DeviceExtension, VioScsiPassiveInitializeRoutine)) {
            return FALSE;
        }
    }

    virtio_device_ready(&adaptExt->vdev);
EXIT_FN();
    return TRUE;
}

BOOLEAN
VioScsiHwReinitialize(
    IN PVOID DeviceExtension
    )
{
    /* The adapter is being restarted and we need to bring it back up without
     * running any passive-level code. Note that VioScsiFindAdapter is *not*
     * called on restart.
     */
    if (!InitVirtIODevice(DeviceExtension)) {
        return FALSE;
    }
    return VioScsiHwInitialize(DeviceExtension);
}

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
ENTER_FN();
    NTSTATUS status = PreProcessRequest(DeviceExtension, (PSRB_TYPE)Srb);
    switch (status)
    {
    case STATUS_SUCCESS:
        CompleteRequest(DeviceExtension, (PSRB_TYPE)Srb);
        break;
    case STATUS_MORE_PROCESSING_REQUIRED:
        return SendSRB(DeviceExtension, (PSRB_TYPE)Srb);
    case STATUS_PENDING:
    default:
        break;
    }
EXIT_FN();
    return TRUE;
}

VOID
HandleResponse(PVOID DeviceExtension, PVirtIOSCSICmd cmd, int queue) {
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE Srb = (PSRB_TYPE)(cmd->srb);
    PSRB_EXTENSION srbExt = SRB_EXTENSION(Srb);
    VirtIOSCSICmdResp *resp = &cmd->resp.cmd;
    UCHAR senseInfoBufferLength = 0;
    PVOID senseInfoBuffer = NULL;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    ULONG srbDataTransferLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    switch (resp->response) {
    case VIRTIO_SCSI_S_OK:
        SRB_SET_SCSI_STATUS(Srb, resp->status);
        srbStatus = (resp->status == SCSISTAT_GOOD) ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_UNDERRUN:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_UNDERRUN");
        srbStatus = SRB_STATUS_DATA_OVERRUN;
        break;
    case VIRTIO_SCSI_S_ABORTED:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_ABORTED");
        srbStatus = SRB_STATUS_ABORTED;
        break;
    case VIRTIO_SCSI_S_BAD_TARGET:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_BAD_TARGET");
        srbStatus = SRB_STATUS_INVALID_TARGET_ID;
        break;
    case VIRTIO_SCSI_S_RESET:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_RESET");
        srbStatus = SRB_STATUS_BUS_RESET;
        break;
    case VIRTIO_SCSI_S_BUSY:
#ifdef ENABLE_WMI
        adaptExt->QueueStats[queue].BusyRequests++;
        adaptExt->TargetStats[SRB_TARGET_ID(Srb)].BusyRequests++;
#endif
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_BUSY");
        srbStatus = SRB_STATUS_BUSY;
        break;
    case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_TRANSPORT_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_TARGET_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_TARGET_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_NEXUS_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_NEXUS_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    default:
        srbStatus = SRB_STATUS_ERROR;
        TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
        break;
    }
    if (srbStatus == SRB_STATUS_SUCCESS &&
        resp->resid &&
        srbDataTransferLen > resp->resid)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbDataTransferLen - resp->resid);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    else if (srbStatus != SRB_STATUS_SUCCESS)
    {
        SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLength);
        if (senseInfoBufferLength >= FIELD_OFFSET(SENSE_DATA, CommandSpecificInformation)) {
            memcpy(senseInfoBuffer, resp->sense,
                min(resp->sense_len, senseInfoBufferLength));
            if (srbStatus == SRB_STATUS_ERROR) {
                srbStatus |= SRB_STATUS_AUTOSENSE_VALID;
            }
        }
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
    }
    else if (srbExt && srbExt->Xfer && srbDataTransferLen > srbExt->Xfer)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbExt->Xfer);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    SRB_SET_SRB_STATUS(Srb, srbStatus);
    CompleteRequest(DeviceExtension, Srb);
}

// Check and respond if control call returned with an error.
void HandleGoogleControlMsg(PVOID DeviceExtension, PVirtIOSCSICmd cmd) {
    if (cmd->req.google.type != VIRTIO_SCSI_T_GOOGLE) {
        return;
    }
    VirtIOSCSICtrlGoogleResp *resp = &cmd->resp.google;
    switch(cmd->req.google.subtype) {
        case VIRTIO_SCSI_T_GOOGLE_REPORT_SNAPSHOT_READY:
            // If the guest is reporting a failure status or a snapshot
            // completion status or the host has returned the control msg with
            // an error status, there will be no resume operation from host.
            // Complete the SRB here so that the guest ioctl can return.
            if (cmd->req.google.data != VIRTIO_SCSI_SNAPSHOT_PREPARE_COMPLETE) {
                CompleteSrbSnapshotCanProceed(DeviceExtension, 0, 0,
                                              SNAPSHOT_STATUS_SUCCEED);
            } else if (resp->response != VIRTIO_SCSI_S_FUNCTION_SUCCEEDED &&
                       resp->response != VIRTIO_SCSI_S_OK) {
                CompleteSrbSnapshotCanProceed(DeviceExtension, 0, 0,
                                              SNAPSHOT_STATUS_INVALID_REQUEST);
            }
            break;
        default:
            break;
    }
}

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    )
{
    PVirtIOSCSICmd      cmd;
    PVirtIOSCSIEventNode evtNode;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    BOOLEAN             isInterruptServiced = FALSE;
    PSRB_TYPE           Srb = NULL;
    ULONG               intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    ENTER_FN1("Irql", KeGetCurrentIrql());
    intReason = virtio_read_isr_status(&adaptExt->vdev);

    if (intReason == 1 || adaptExt->dump_mode) {
        struct virtqueue *vq = adaptExt->vq[VIRTIO_SCSI_REQUEST_QUEUE_0];
        isInterruptServiced = TRUE;

        virtqueue_disable_cb(vq);
        do {
            while ((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(vq, &len)) != NULL) {
                HandleResponse(DeviceExtension, cmd, 0);
            }
        } while (!virtqueue_enable_cb(vq));

        while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL) {
            if (cmd->req.tmf.type == VIRTIO_SCSI_T_TMF) {
                Srb = (PSRB_TYPE)cmd->srb;
                ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
                StorPortResume(DeviceExtension);
            } else if (cmd->req.tmf.type == VIRTIO_SCSI_T_GOOGLE) {
                HandleGoogleControlMsg(DeviceExtension, cmd);
            }
            VirtIOSCSICtrlTMFResp *resp;
            resp = &cmd->resp.tmf;
            switch(resp->response) {
            case VIRTIO_SCSI_S_OK:
            case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                break;
            default:
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
                ASSERT(0);
                break;
            }
        }
        adaptExt->tmf_infly = FALSE;
        while((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) != NULL) {
           PVirtIOSCSIEvent evt = &evtNode->event;
           switch (evt->event) {
           case VIRTIO_SCSI_T_NO_EVENT:
               break;
           case VIRTIO_SCSI_T_TRANSPORT_RESET:
               TransportReset(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_PARAM_CHANGE:
               ParamChange(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_START:
               RequestSnapshot(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_COMPLETE:
               ProcessSnapshotCompletion(DeviceExtension, evt);
               break;
           default:
               TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unsupport virtio scsi", "event", evt->event);
               break;
           }
           SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
    }
    TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_IO, "ISR", "isInterruptServiced", isInterruptServiced);
    return isInterruptServiced;
}

#if (MSI_SUPPORTED == 1)
static BOOLEAN
VioScsiMSInterruptWorker(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageID
    )
{
    PVirtIOSCSICmd      cmd;
    PVirtIOSCSIEventNode evtNode;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    PSRB_TYPE           Srb = NULL;
    ULONG               intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    ENTER_FN1("MessageID", MessageID);

    if (MessageID > 2)
    {
#ifdef ENABLE_WMI
        adaptExt->QueueStats[MessageID - 3].TotalInterrupts++;
#endif
        DispatchQueue(DeviceExtension, MessageID);
        return TRUE;
    }
    if (MessageID == 0)
    {
       return TRUE;
    }
    if (MessageID == 1)
    {
         while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL)
         {
            if (cmd->req.tmf.type == VIRTIO_SCSI_T_TMF) {
                Srb = (PSRB_TYPE)cmd->srb;
                ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
                StorPortResume(DeviceExtension);
            } else if (cmd->req.tmf.type == VIRTIO_SCSI_T_GOOGLE) {
                HandleGoogleControlMsg(DeviceExtension, cmd);
            }
            VirtIOSCSICtrlTMFResp *resp;
            resp = &cmd->resp.tmf;
            switch(resp->response) {
            case VIRTIO_SCSI_S_OK:
            case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                break;
            default:
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
                ASSERT(0);
                break;
            }
        }
        adaptExt->tmf_infly = FALSE;
        return TRUE;
    }
    if (MessageID == 2) {
        while((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) != NULL) {
           PVirtIOSCSIEvent evt = &evtNode->event;
           switch (evt->event) {
           case VIRTIO_SCSI_T_NO_EVENT:
               break;
           case VIRTIO_SCSI_T_TRANSPORT_RESET:
               TransportReset(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_PARAM_CHANGE:
               ParamChange(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_START:
               RequestSnapshot(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_COMPLETE:
               ProcessSnapshotCompletion(DeviceExtension, evt);
               break;
           default:
               TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unsupport virtio scsi", "event", evt->event);
               break;
           }
           SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
VioScsiMSInterrupt(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageID
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN isInterruptServiced = FALSE;
    ULONG i;

    if (!adaptExt->msix_one_vector) {
        /* Each queue has its own vector, this is the fast and common case */
        return VioScsiMSInterruptWorker(DeviceExtension, MessageID);
    }

    /* Fall back to checking all queues */
    for (i = 0; i < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; i++) {
        if (virtqueue_has_buf(adaptExt->vq[i])) {
            isInterruptServiced |= VioScsiMSInterruptWorker(DeviceExtension, i + 1);
        }
    }
    return isInterruptServiced;
}
#endif

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    )
{
    TRACE_CONTEXT_NO_SRB();
    UNREFERENCED_PARAMETER(PathId);

    TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "Bus reset!");
    return DeviceReset(DeviceExtension);
}

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    )
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG                             AdjustedMaxControlType;
    ULONG                             Index;
    PADAPTER_EXTENSION                adaptExt;
    SCSI_ADAPTER_CONTROL_STATUS       status = ScsiAdapterControlUnsuccessful;
    BOOLEAN SupportedConrolTypes[5] = {TRUE, TRUE, TRUE, FALSE, FALSE};
    TRACE_CONTEXT_NO_SRB();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

ENTER_FN1("ControlType", ControlType);

    switch (ControlType) {

    case ScsiQuerySupportedControlTypes: {
        ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
        AdjustedMaxControlType =
            (ControlTypeList->MaxControlType < 5) ?
            ControlTypeList->MaxControlType :
            5;
        for (Index = 0; Index < AdjustedMaxControlType; Index++) {
            ControlTypeList->SupportedTypeList[Index] =
                SupportedConrolTypes[Index];
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiStopAdapter: {
        ShutDown(DeviceExtension);
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiRestartAdapter: {
        ShutDown(DeviceExtension);
        if (!VioScsiHwReinitialize(DeviceExtension))
        {
           TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot reinitialize HW");
           break;
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    default:
        break;
    }

EXIT_FN();
    return status;
}

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
    PCDB                  cdb;
    ULONG                 i;
    ULONG                 fragLen;
    ULONG                 sgElement;
    ULONG                 sgMaxElements;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
    PSTOR_SCATTER_GATHER_LIST sgList;
    VirtIOSCSICmd         *cmd;
    UCHAR                 TargetId;
    UCHAR                 Lun;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    PROCESSOR_NUMBER ProcNumber;
    ULONG processor = KeGetCurrentProcessorNumberEx(&ProcNumber);
    ULONG cpu = ProcNumber.Number;
#else
    ULONG cpu = KeGetCurrentProcessorNumber();
#endif

ENTER_FN();
    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TargetId = SRB_TARGET_ID(Srb);
    Lun      = SRB_LUN(Srb);

    if ((SRB_PATH_ID(Srb) > 0) ||
        (TargetId >= adaptExt->scsi_config.max_target) ||
        (Lun >= adaptExt->scsi_config.max_lun) ) {
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_NO_DEVICE);
        StorPortNotification(RequestComplete,
                             DeviceExtension,
                             Srb);
        return FALSE;
    }

    TRACE4(TRACE_LEVEL_VERBOSE, DRIVER_IO, "SrbInfo",
        "OpCode", ((PCDB)Srb->Cdb)->CDB6GENERIC.OperationCode,
        "PathId", Srb->PathId, "TargetId", Srb->TargetId, "Lun", Srb->Lun);

#ifdef DEBUG
    memset(srbExt, 0xFF, sizeof(SRB_EXTENSION));
#endif
    srbExt->Xfer = 0;
    srbExt->Srb = Srb;
    srbExt->cpu = (UCHAR)cpu;
    cmd = &srbExt->cmd;
    cmd->srb = (PVOID)Srb;
    cmd->comp = NULL;
    cmd->req.cmd.lun[0] = 1;
    cmd->req.cmd.lun[1] = TargetId;
    cmd->req.cmd.lun[2] = 0;
    cmd->req.cmd.lun[3] = Lun;
    cmd->req.cmd.lun[4] = 0;
    cmd->req.cmd.lun[5] = 0;
    cmd->req.cmd.lun[6] = 0;
    cmd->req.cmd.lun[7] = 0;
    cmd->req.cmd.tag = (ULONG_PTR)(Srb);
    cmd->req.cmd.task_attr = VIRTIO_SCSI_S_SIMPLE;
    cmd->req.cmd.prio = 0;
    cmd->req.cmd.crn = 0;
    if (cdb != NULL) {
        memcpy(cmd->req.cmd.cdb, cdb, min(VIRTIO_SCSI_CDB_SIZE, SRB_CDB_LENGTH(Srb)));
    }

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.cmd, &fragLen);
    srbExt->sg[sgElement].length   = sizeof(cmd->req.cmd);
    sgElement++;

    sgList = StorPortGetScatterGatherList(DeviceExtension, Srb);
    if (sgList)
    {
        sgMaxElements = sgList->NumberOfElements;

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) == SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->sg[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->sg[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.cmd, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.cmd);
    sgElement++;
    if (sgList)
    {
        sgMaxElements = sgList->NumberOfElements;

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) != SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->sg[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->sg[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->in = sgElement - srbExt->out;

EXIT_FN();
    return TRUE;
}

VOID
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID
    )
{
    PADAPTER_EXTENSION  adaptExt;
    ULONG queue;
    ULONG cpu;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    PROCESSOR_NUMBER ProcNumber;
    KeGetCurrentProcessorNumberEx(&ProcNumber);
    cpu = ProcNumber.Number;
#else
    cpu = KeGetCurrentProcessorNumber();
#endif
ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    queue = MessageID - 3;
    if (adaptExt->num_queues == 1) {
        cpu = 0;
    }
    if (!adaptExt->dump_mode && adaptExt->dpc_ok && MessageID > 0) {
        // FIXME: This will fail with cpu hot plug.
        StorPortIssueDpc(DeviceExtension,
            &adaptExt->dpc[queue],
            ULongToPtr(MessageID),
            ULongToPtr(cpu));
EXIT_FN();
        return;
    }
    ProcessQueue(DeviceExtension, MessageID, FALSE);
EXIT_FN();
}

VOID
ProcessQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN BOOLEAN isr
    )
{
    PVirtIOSCSICmd      cmd;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    ULONG               msg = MessageID - 3;
    STOR_LOCK_HANDLE    queueLock = { 0 };
    struct virtqueue    *vq;
    BOOLEAN             handleResponseInline;
#ifdef USE_WORK_ITEM
#if (NTDDI_VERSION > NTDDI_WIN7)
    UCHAR               cnt = 0;
    PSRB_TYPE           Srb = NULL;
    PVOID               Worker = NULL;
    ULONG               status = STOR_STATUS_SUCCESS;
#endif
#endif
#ifdef ENABLE_WMI
    ULONGLONG           tsc = 0;
    ULONGLONG           srbLatency;
    ULONG               TargetId;
#endif
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    handleResponseInline = (adaptExt->num_queues == 1);
ENTER_FN();
#ifdef USE_WORK_ITEM
#if (NTDDI_VERSION > NTDDI_WIN7)
     if (!handleResponseInline) {
         status = StorPortInitializeWorker(DeviceExtension, &Worker);
         if (status != STOR_STATUS_SUCCESS) {
             TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "StorPortInitializeWorker failed", "status", status);
             handleResponseInline = TRUE;
         }
     }
#else
    handleResponseInline = TRUE;
#endif
#else
    handleResponseInline = TRUE;
#endif
#ifdef ENABLE_WMI
    tsc = ReadTimeStampCounter();
#endif
    vq = adaptExt->vq[VIRTIO_SCSI_REQUEST_QUEUE_0 + msg];

    VioScsiVQLock(DeviceExtension, MessageID, &queueLock, isr);

    virtqueue_disable_cb(vq);
    do {
        while ((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(vq, &len)) != NULL) {
            if (handleResponseInline) {
                HandleResponse(DeviceExtension, cmd, msg);
            }
#ifdef USE_WORK_ITEM
            else {
#if (NTDDI_VERSION > NTDDI_WIN7)
                Srb = (PSRB_TYPE)(cmd->srb);
                PSRB_EXTENSION srbExt = SRB_EXTENSION(Srb);
                PSTOR_SLIST_ENTRY Result = NULL;
#ifdef ENABLE_WMI
                TargetId = SRB_TARGET_ID(Srb);
                adaptExt->QueueStats[msg].CompletedRequests++;
                adaptExt->TargetStats[TargetId].CompletedRequests++;
                srbLatency = tsc - srbExt->startTsc;
                if (srbLatency > adaptExt->QueueStats[msg].MaxLatency) adaptExt->QueueStats[msg].MaxLatency = srbLatency;
                if (srbLatency > adaptExt->TargetStats[TargetId].MaxLatency) adaptExt->TargetStats[TargetId].MaxLatency = srbLatency;
#endif
                VioScsiVQUnlock(DeviceExtension, MessageID, &queueLock, isr);
                srbExt->priv = (PVOID)cmd;
                status = StorPortInterlockedPushEntrySList(DeviceExtension, &adaptExt->srb_list[msg], &srbExt->list_entry, &Result);
                if (status != STOR_STATUS_SUCCESS) {
                    HandleResponse(DeviceExtension, cmd, msg);
                    TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "StorPortInterlockedPushEntrySList failed", "status", status);
                }
                cnt++;
                VioScsiVQLock(DeviceExtension, MessageID, &queueLock, isr);
#else
                NT_ASSERT(0);
#endif
            }
#endif
        }
    } while (!virtqueue_enable_cb(vq));

    VioScsiVQUnlock(DeviceExtension, MessageID, &queueLock, isr);
#ifdef USE_WORK_ITEM
#if (NTDDI_VERSION > NTDDI_WIN7)
    Srb = NULL;
    if (cnt) {
        status = StorPortQueueWorkItem(DeviceExtension, &VioScsiWorkItemCallback, Worker, ULongToPtr(MessageID));
        if (status != STOR_STATUS_SUCCESS && status != STOR_STATUS_BUSY) {
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "StorPortQueueWorkItem failed", "status", status);
//FIXME   VioScsiWorkItemCallback
       }
    } else {
       if (Worker != NULL) {
           StorPortFreeWorker(DeviceExtension, Worker);
       }
    }
#endif
#endif
EXIT_FN();
}

VOID
VioScsiCompleteDpcRoutine(
    IN PSTOR_DPC  Dpc,
    IN PVOID Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    )
{
    ULONG MessageId;

    MessageId = PtrToUlong(SystemArgument1);
    ProcessQueue(Context, MessageId, FALSE);
}

VOID
CompleteSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN BOOLEAN DeviceAck
    )
{
    PSRB_TYPE Srb = ClearSrbSnapshotRequested(adaptExt);
    if (Srb) {
        PSRB_VSS_BUFFER vssBuffer = (PSRB_VSS_BUFFER)SRB_DATA_BUFFER(Srb);
        vssBuffer->SrbIoControl.ReturnCode = SNAPSHOT_STATUS_SUCCEED;
        vssBuffer->Target = Target;
        vssBuffer->Lun = Lun;

        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        CompleteRequest(adaptExt, Srb);
    } else {
         if (DeviceAck) {
             // No pending Srb found, report that Vss snapshots are currently
             // unavailable.
             ReportSnapshotStatus(adaptExt, NULL, Target, Lun,
                                  VIRTIO_SCSI_SNAPSHOT_PREPARE_UNAVAILABLE);
         }
    }
}

VOID
CompleteSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN ULONG ReturnCode
    )
{
    PSRB_TYPE Srb = ClearSrbSnapshotCanProceed(adaptExt);
    if (Srb) {
        PSRB_VSS_BUFFER vssBuffer = (PSRB_VSS_BUFFER)SRB_DATA_BUFFER(Srb);
        vssBuffer->SrbIoControl.ReturnCode = ReturnCode;
        vssBuffer->Target = Target;
        vssBuffer->Lun = Lun;

        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        CompleteRequest(adaptExt, Srb);
    }
}

// For the request being processed, return appropriate status back to the
// StartIo driver entry.
//   STATUS_SUCCESS:
//       the request has been successfully processed and can be "completed".
//   STATUS_PENDING:
//       the request is not finished yet and will be left in pending state.
//   STATUS_BUSY:
//       the request will be discarded without processing.
//   STATUS_MORE_PROCESSING_REQUIRED:
//       the SRB will be sent to the device for more processing.
NTSTATUS
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG PnPFlags = 0;
    ULONG PnPAction = 0;
    PSTOR_DEVICE_CAPABILITIES_TYPE pDevCapabilities = NULL;
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (SRB_FUNCTION(Srb)) {
        case SRB_FUNCTION_PNP:
#if (NTDDI_VERSION > NTDDI_WIN7)
            SRB_GET_PNP_INFO(Srb, PnPFlags, PnPAction);
            if (((PnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST) == 0) &&
                (PnPAction == StorQueryCapabilities) &&
                (SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(STOR_DEVICE_CAPABILITIES))) {
                pDevCapabilities = (PSTOR_DEVICE_CAPABILITIES_TYPE)SRB_DATA_BUFFER(Srb);
                pDevCapabilities->Version = 0;
                pDevCapabilities->DeviceD1 = 0;
                pDevCapabilities->DeviceD2 = 0;
                pDevCapabilities->LockSupported = 0;
                pDevCapabilities->EjectSupported = 0;
                pDevCapabilities->Removable = 1;
                pDevCapabilities->DockDevice = 0;
                pDevCapabilities->UniqueID = 0;
                pDevCapabilities->SilentInstall = 0;
                pDevCapabilities->SurpriseRemovalOK = 1;
                pDevCapabilities->NoDisplayInUI = 0;
            }
#endif
            // fallthrough
        case SRB_FUNCTION_POWER: {
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            status = STATUS_SUCCESS;
            break;
        }
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
#ifdef ENABLE_WMI
            adaptExt->TargetStats[SRB_TARGET_ID(Srb)].ResetRequests++;
#endif
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_BUS:
            TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Hierarchical reset", "function", adaptExt->queue_depth);
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            status = STATUS_SUCCESS;
            break;
#ifdef ENABLE_WMI
        case SRB_FUNCTION_WMI:
            WmiSrb(adaptExt, Srb);
            status = STATUS_SUCCESS;
            break;
#endif
        case SRB_FUNCTION_IO_CONTROL:
            return VioScsiIoControl(DeviceExtension, Srb);
    }
EXIT_FN();
    return status;
}

VOID
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PCDB                  cdb;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
#ifdef ENABLE_WMI
    ULONG                 target, TargetId;
#endif

ENTER_FN();
    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (cdb == NULL) return;
    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_READ_CAPACITY16:
            if (!StorPortSetDeviceQueueDepth(DeviceExtension, SRB_PATH_ID(Srb),
                SRB_TARGET_ID(Srb), SRB_LUN(Srb), adaptExt->queue_depth)) {
               TRACE1(TRACE_LEVEL_ERROR, DRIVER_IO, "StorPortSetDeviceQueueDepth failed", "queue_depth", adaptExt->queue_depth);
           }
#ifdef ENABLE_WMI
           // Update adaptExt->MaxLun with interlocked operations.
           // There is a chance that another thread will collide with this and we will have
           // to iterate again, but it's very small.
            TargetId = (ULONG)SRB_TARGET_ID(Srb);
            while ((target = adaptExt->MaxTarget) < TargetId + 1) {
                InterlockedCompareExchange(&adaptExt->MaxTarget, TargetId + 1, target);
            }
#endif
           break;
        case SCSIOP_INQUIRY:
            VioScsiSaveInquiryData(DeviceExtension, Srb);
           break;
        default:
           break;

    }
EXIT_FN();
}

VOID
CompleteRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
ENTER_FN();
    PostProcessRequest(DeviceExtension, Srb);
    StorPortNotification(RequestComplete,
                         DeviceExtension,
                         Srb);
EXIT_FN();
}

VOID
LogError(
    IN PVOID DeviceExtension,
    IN ULONG ErrorCode,
    IN ULONG UniqueId
    )
{
#if (NTDDI_VERSION > NTDDI_WIN7)
    STOR_LOG_EVENT_DETAILS logEvent;
    ULONG sz = 0;
    memset( &logEvent, 0, sizeof(logEvent) );
    logEvent.InterfaceRevision         = STOR_CURRENT_LOG_INTERFACE_REVISION;
    logEvent.Size                      = sizeof(logEvent);
    logEvent.EventAssociation          = StorEventAdapterAssociation;
    logEvent.StorportSpecificErrorCode = TRUE;
    logEvent.ErrorCode                 = ErrorCode;
    logEvent.DumpDataSize              = sizeof(UniqueId);
    logEvent.DumpData                  = &UniqueId;
    StorPortLogSystemEvent( DeviceExtension, &logEvent, &sz );
#else
    StorPortLogError(DeviceExtension,
                         NULL,
                         0,
                         0,
                         0,
                         ErrorCode,
                         UniqueId);
#endif
}

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    TRACE_CONTEXT_NO_SRB();
    switch (evt->reason)
    {
        case VIRTIO_SCSI_EVT_RESET_RESCAN:
            StorPortNotification( BusChangeDetected, DeviceExtension, 0);
            break;
        case VIRTIO_SCSI_EVT_RESET_REMOVED:
            StorPortNotification( BusChangeDetected, DeviceExtension, 0);
            break;
        default:
            TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_START, "<-->Unsupport virtio scsi event reason", "reason", evt->reason);
    }
}


bool
DecodeAddress(
    UCHAR* TargetId,
    UCHAR* LunId,
    const u8 lun[8]
    )
{
    // Interleaved quotes from virtio spec follow.
    // "first byte set to 1,"
    if (lun[0] != 1) {
        return false;
    }

    // "second byte set to target,"
    *TargetId = lun[1];

    *LunId = ((lun[2] & 0x3F) << 8) | lun[3];

    // "followed by four zero bytes."
    if (lun[4] || lun[5] || lun[6] || lun[7]) {
        return false;
    }

    return true;
}

void
RequestSnapshot(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    UCHAR targetId;
    UCHAR lunId;

    if (DecodeAddress(&targetId, &lunId, evt->lun)) {
        CompleteSrbSnapshotRequested(adaptExt, targetId, lunId, true);
    }
}

VOID
ProcessSnapshotCompletion(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    UCHAR targetId;
    UCHAR lunId;

    if (DecodeAddress(&targetId, &lunId, evt->lun)) {
        CompleteSrbSnapshotCanProceed(adaptExt, targetId, lunId,
                                      SNAPSHOT_STATUS_SUCCEED);
    }
}

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    UCHAR TargetId = evt->lun[1];
    UCHAR Lun = (evt->lun[2] << 8) | evt->lun[3];
    UCHAR AdditionalSenseCode = (UCHAR)(evt->reason & 255);
    UCHAR AdditionalSenseCodeQualifier = (UCHAR)(evt->reason >> 8);

    if (AdditionalSenseCode == SCSI_ADSENSE_PARAMETERS_CHANGED &&
       (AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED))
    {
        StorPortNotification( BusChangeDetected, DeviceExtension, 0);
    }
}

NTSTATUS
VioScsiIoControl(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    )
{
    PSRB_IO_CONTROL srbControl;
    PVOID           srbDataBuffer = SRB_DATA_BUFFER(Srb);
    PADAPTER_EXTENSION    adaptExt;
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;

ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    srbControl = (PSRB_IO_CONTROL)srbDataBuffer;

    switch (srbControl->ControlCode) {
        case IOCTL_SCSI_MINIPORT_NOT_QUORUM_CAPABLE:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "Not quorum capable", "Signature", *(ULONGLONG*)(&srbControl->Signature));
            break;
        case IOCTL_SNAPSHOT_REQUESTED:
           if ((SRB_DATA_TRANSFER_LENGTH(Srb) <
                 srbControl->Length + sizeof(SRB_IO_CONTROL)) ||
                SRB_DATA_TRANSFER_LENGTH(Srb) < sizeof(SRB_VSS_BUFFER)) {

                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
                srbControl->ReturnCode = SNAPSHOT_STATUS_INVALID_REQUEST;
                status = STATUS_SUCCESS;
            } else if (!SetSrbSnapshotRequested(adaptExt, Srb)) {
                // If there is an existing pending request, discard
                // any new request until the current one completes.
                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                status = STATUS_SUCCESS;
            } else {
                // We are not completing the request right away,
                // it will stay pending.
                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_PENDING);
                status = STATUS_PENDING;
            }
            break;
        case IOCTL_SNAPSHOT_CAN_PROCEED:
            if ((SRB_DATA_TRANSFER_LENGTH(Srb) <
                 srbControl->Length + sizeof(SRB_IO_CONTROL)) ||
                SRB_DATA_TRANSFER_LENGTH(Srb) < sizeof(SRB_VSS_BUFFER)) {

                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
                srbControl->ReturnCode = SNAPSHOT_STATUS_INVALID_REQUEST;
                status = STATUS_SUCCESS;
            } else if (!SetSrbSnapshotCanProceed(adaptExt, Srb)) {
                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                status = STATUS_SUCCESS;
            } else {
                PSRB_VSS_BUFFER vssBuf= (PSRB_VSS_BUFFER)SRB_DATA_BUFFER(Srb);
                if (ReportSnapshotStatus(adaptExt,
                                         Srb,
                                         vssBuf->Target,
                                         vssBuf->Lun,
                                         vssBuf->Status)) {
                    // SRB will be completed once the backend send
                    // event to resume writer.
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_PENDING);
                    status = STATUS_PENDING;
                } else {
                    // Sth went wrong.
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                    status = STATUS_SUCCESS;
                }
            }
            break;
        case IOCTL_SNAPSHOT_DISCARD:
            // Discard any pending SRB for snapshot.
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            CompleteSrbSnapshotRequested(adaptExt, 0, 0, false);
            CompleteSrbSnapshotCanProceed(
                adaptExt, 0, 0, SNAPSHOT_STATUS_CANCELLED);
            status = STATUS_SUCCESS;
            break;
        default:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
            TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_IO, "Unsupported control code", "code", srbControl->ControlCode);
            break;
    }
EXIT_FN();
    return status;
}

VOID
VioScsiSaveInquiryData(
    IN PVOID  DeviceExtension,
    IN OUT PSRB_TYPE Srb
    )
{
    PVOID           dataBuffer;
    PADAPTER_EXTENSION    adaptExt;
    PCDB cdb;
    PINQUIRYDATA InquiryData;
    ULONG dataLen;

ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    cdb      = SRB_CDB(Srb);
    dataBuffer = SRB_DATA_BUFFER(Srb);
    InquiryData = (PINQUIRYDATA)dataBuffer;
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);
    switch (cdb->CDB6INQUIRY3.PageCode) {
        case VPD_SERIAL_NUMBER: {
            PVPD_SERIAL_NUMBER_PAGE SerialPage;
            SerialPage = (PVPD_SERIAL_NUMBER_PAGE)dataBuffer;
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "VPD_SERIAL_NUMBER", "PageLength", SerialPage->PageLength);
            if (SerialPage->PageLength > 0 && adaptExt->ser_num == NULL) {
                int ln = min (64, SerialPage->PageLength);
                ULONG Status =
                             StorPortAllocatePool(DeviceExtension,
                             ln + 1,
                             VIOSCSI_POOL_TAG,
                             (PVOID*)&adaptExt->ser_num);
                if (NT_SUCCESS(Status)) {
                    StorPortMoveMemory(adaptExt->ser_num, SerialPage->SerialNumber, ln);
                    adaptExt->ser_num[ln] = '\0';
                    TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "Serial number", "value", adaptExt->ser_num);
                }
            }
            break;
        }
        case VPD_DEVICE_IDENTIFIERS: {
            PVPD_IDENTIFICATION_PAGE IdentificationPage;
            PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr;
            IdentificationPage = (PVPD_IDENTIFICATION_PAGE)dataBuffer;
            if (IdentificationPage->PageLength >= sizeof(VPD_IDENTIFICATION_DESCRIPTOR)) {
                IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)IdentificationPage->Descriptors;
                TRACE3(TRACE_LEVEL_FATAL, DRIVER_IO, "VPD_DEVICE_IDENTIFIERS", "CodeSet", IdentificationDescr->CodeSet, "IdentifierType", IdentificationDescr->IdentifierType, "IdentifierLength", IdentificationDescr->IdentifierLength);
                if (IdentificationDescr->IdentifierLength >= (sizeof(ULONGLONG)) && (IdentificationDescr->CodeSet == VpdCodeSetBinary)) {
                    REVERSE_BYTES_QUAD(&adaptExt->hba_id, &IdentificationDescr->Identifier[8]);
                    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_IO, "Device identifiers", "identifier", *(ULONGLONG*)(&IdentificationDescr->Identifier), "hba", adaptExt->hba_id);
                }
            }
            break;
        }
        default:
            TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_IO, "Unhandled page code", "page code", cdb->CDB6INQUIRY3.PageCode);
            break;
    }

EXIT_FN();
}

#ifdef USE_WORK_ITEM
#if (NTDDI_VERSION > NTDDI_WIN7)
VOID
VioScsiWorkItemCallback(
    _In_ PVOID DeviceExtension,
    _In_opt_ PVOID Context,
    _In_ PVOID Worker
    )
{
    ULONG MessageId = PtrToUlong(Context);
    ULONG status = STOR_STATUS_SUCCESS;
    ULONG msg = MessageId - 3;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSTOR_SLIST_ENTRY   listEntryRev, listEntry;
    PSRB_TYPE Srb = NULL;
ENTER_FN();
    status = StorPortInterlockedFlushSList(DeviceExtension, &adaptExt->srb_list[msg], &listEntryRev);
    if ((status == STOR_STATUS_SUCCESS) && (listEntryRev != NULL)) {
        KAFFINITY old_affinity, new_affinity;
        old_affinity = new_affinity = 0;
#if 1
        listEntry = listEntryRev;
#else
        listEntry = NULL;
        while (listEntryRev != NULL) {
            next = listEntryRev->Next;
            listEntryRev->Next = listEntry;
            listEntry = listEntryRev;
            listEntryRev = next;
        }
#endif
        while(listEntry)
        {
            PVirtIOSCSICmd  cmd = NULL;
            PSRB_EXTENSION srbExt = NULL;
            PSTOR_SLIST_ENTRY next = listEntry->Next;
            srbExt = CONTAINING_RECORD(listEntry,
                        SRB_EXTENSION, list_entry);

            ASSERT(srbExt);
            Srb = (PSRB_TYPE)(srbExt->Srb);
            cmd = (PVirtIOSCSICmd)srbExt->priv;
            ASSERT(cmd);
            if (new_affinity == 0) {
                new_affinity = ((KAFFINITY)1) << srbExt->cpu;
                old_affinity = KeSetSystemAffinityThreadEx(new_affinity);
            }
            HandleResponse(DeviceExtension, cmd, msg);
            listEntry = next;
        }
        if (new_affinity != 0) {
            KeRevertToUserAffinityThreadEx(old_affinity);
        }
    }
    else if (status != STOR_STATUS_SUCCESS) {
       TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO, "StorPortInterlockedPushEntrySList failed", "status", status);
    }

    status = StorPortFreeWorker(DeviceExtension, Worker);
    Srb = NULL;
    if (status != STOR_STATUS_SUCCESS) {
       TRACE1(TRACE_LEVEL_FATAL, DRIVER_IO,  "StorPortFreeWorker failed", "status", status);
    }
EXIT_FN();
}
#endif
#endif
