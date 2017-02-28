#ifdef ENABLE_WMI
#include "vioscsi.h"
#include "utils.h"
#include "helper.h"
#include "resources.h"
#include "wmidata.h"

#define MS_SM_HBA_API
#include <hbapiwmi.h>
#include <hbaapi.h>
#include <ntddscsi.h>

UCHAR
VioScsiQueryWmiRegInfo(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    _Out_ PWCHAR *MofResourceName);

BOOLEAN
VioScsiQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer);

UCHAR
VioScsiExecuteWmiMethod(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG MethodId,
    IN ULONG InBufferSize,
    IN ULONG OutBufferSize,
    IN OUT PUCHAR Buffer
    );

VOID
VioScsiReadExtendedData(
    IN PVOID Context,
    OUT PUCHAR Buffer
    );

BOOLEAN
VioScsiPdoQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer);

UCHAR
BuildVirtQueueStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer,
    OUT PULONG SizeNeeded);

UCHAR
BuildTargetStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer,
    OUT PULONG SizeNeeded);

//
// The index numbers should correspond to the offset in
// WmiGuidList array given below.
//
#define VirtQueueStatistics_GUID_INDEX 0
GUID VirtQueueStatisticsGuid = VirtQueue_StatisticsGuid;

#define VioScsiWmiExtendedInfo_GUID_INDEX 1
#define VIOSCSI_SETUP_GUID_INDEX 1
GUID VioScsiWmiExtendedInfoGuid = VioScsiWmi_ExtendedInfo_Guid;

#define VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX 2
GUID VioScsiWmiAdaperInformationQueryGuid = MS_SM_AdapterInformationQueryGuid;

#define VIOSCSI_MS_PORT_INFORM_GUID_INDEX 3
GUID VioScsiWmiPortInformationMethodsGuid = MS_SM_PortInformationMethodsGuid;

//
// GUID List and number of GUIDs in the list for the adapter WMI.
//
SCSIWMIGUIDREGINFO WmiGuidList[] =
{
    {
        &VirtQueueStatisticsGuid,
        0xffffffff, //dynamic instance names
        0
    },
    {
        &VioScsiWmiExtendedInfoGuid,
        1,
        0
    },
    {
        &VioScsiWmiAdaperInformationQueryGuid,
        1,
        0
    },
    {
        &VioScsiWmiPortInformationMethodsGuid,
        1,
        0
    },
};

#define WmiGuidCount (sizeof(WmiGuidList) / sizeof(SCSIWMIGUIDREGINFO))

//
// The index numbers should correspond to the offset in
// PdoWmiGuidList array given below.
//
#define TargetStatistics_GUID_INDEX 0
GUID TargetStatisticsGuid = Target_StatisticsGuid;

//
// GUID List and number of GUIDs in the list for the PDO WMI.
//
SCSIWMIGUIDREGINFO PdoWmiGuidList[] =
{
    {
        &TargetStatisticsGuid,
        0xffffffff, //dynamic instance names
        0
    },
};

#define PdoWmiGuidCount (sizeof(PdoWmiGuidList) / sizeof(SCSIWMIGUIDREGINFO))

#define WmiMofResourceName L"MofResource"

VOID
WmiInitializeContext(
    IN PADAPTER_EXTENSION AdapterExtension
    )
/*+++

Routine Description:

    This routine will initialize the wmilib context structure with the
    guid list and the pointers to the wmilib callback functions.

Arguments:

    AdapterExtension - Adpater extension

Return Value:

    None.

--*/
{
    PSCSI_WMILIB_CONTEXT wmiLibContext;

    // Initialize the wmilib context for the adapter
    wmiLibContext = &(AdapterExtension->WmiLibContext);

    wmiLibContext->GuidList = WmiGuidList;
    wmiLibContext->GuidCount = WmiGuidCount;

    // Set pointers to WMI callback routines
    wmiLibContext->QueryWmiRegInfo = VioScsiQueryWmiRegInfo;
    wmiLibContext->QueryWmiDataBlock = VioScsiQueryWmiDataBlock;
    wmiLibContext->ExecuteWmiMethod = NULL;
    wmiLibContext->WmiFunctionControl = NULL;
    wmiLibContext->SetWmiDataItem = NULL;
    wmiLibContext->SetWmiDataBlock = NULL;

    // Initialize the wmilib context for the pdo
    wmiLibContext = &(AdapterExtension->PdoWmiLibContext);

    wmiLibContext->GuidList = PdoWmiGuidList;
    wmiLibContext->GuidCount = PdoWmiGuidCount;

    // Set pointers to WMI callback routines
    wmiLibContext->QueryWmiRegInfo = VioScsiQueryWmiRegInfo;
    wmiLibContext->QueryWmiDataBlock = VioScsiPdoQueryWmiDataBlock;
    wmiLibContext->ExecuteWmiMethod = VioScsiExecuteWmiMethod;
    wmiLibContext->WmiFunctionControl = NULL;
    wmiLibContext->SetWmiDataItem = NULL;
    wmiLibContext->SetWmiDataBlock = NULL;
}

BOOLEAN
WmiSrb(
    IN     PADAPTER_EXTENSION   AdapterExtension,
    IN OUT PSRB_TYPE            Srb
    )
/*++

Routine Description:

   Called from StartIo routine to process an SRB_FUNCTION_WMI request.
   Main entry point for all WMI routines.

Arguments:

   AdapterExtension - ISCSI miniport driver's Adapter extension.

   Srb              - IO request packet.

Return Value:

   Always TRUE.

--*/
{
    BOOLEAN adapterRequest;
    SCSIWMI_REQUEST_CONTEXT requestContext = {0};
    PSRB_WMI_DATA pSrbWmi = SRB_WMI_DATA(Srb);

    // Check if the WMI SRB is targetted for the adapter or one of the devices
    adapterRequest = (pSrbWmi->WMIFlags & SRB_WMI_FLAGS_ADAPTER_REQUEST) == SRB_WMI_FLAGS_ADAPTER_REQUEST;
    // Note: the dispatch functions are not allowed to pend the srb.
    ScsiPortWmiDispatchFunction(
        adapterRequest ? &AdapterExtension->WmiLibContext : &AdapterExtension->PdoWmiLibContext,
        pSrbWmi->WMISubFunction,
        AdapterExtension,
        &requestContext,
        pSrbWmi->DataPath,
        SRB_DATA_TRANSFER_LENGTH(Srb),
        SRB_DATA_BUFFER(Srb));
    SRB_SET_DATA_TRANSFER_LENGTH(Srb, ScsiPortWmiGetReturnSize(&requestContext));
    SRB_SET_SRB_STATUS(Srb, ScsiPortWmiGetReturnStatus(&requestContext));

    return TRUE;
}

UCHAR
VioScsiQueryWmiRegInfo(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    _Out_ PWCHAR *MofResourceName
    )
/*+++

Routine Description:

    This routine returns MofResourceName for this driver.

--*/
{
    *MofResourceName = WmiMofResourceName;
    return SRB_STATUS_SUCCESS;
}

void CopyWMIString(void* _pDest, const void* _pSrc, size_t _maxlength)
{
     PUSHORT _pDestTemp = _pDest;
     USHORT  _length = _maxlength - sizeof(USHORT);
                                                                                                                                                 \
     *_pDestTemp++ = _length;
                                                                                                                                                 \
     _length = (USHORT)min(wcslen(_pSrc)*sizeof(WCHAR), _length);
     memcpy(_pDestTemp, _pSrc, _length);
}

BOOLEAN
VioScsiQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer
    )
/*+++

Routine Description :

    Called to query WMI Data blocks

--*/
{
    UCHAR status = SRB_STATUS_ERROR;
    ULONG sizeNeeded = 0;
    PADAPTER_EXTENSION adapterExtension = (PADAPTER_EXTENSION) Context;

    switch (GuidIndex) {
    case VirtQueueStatistics_GUID_INDEX: {
            status = BuildVirtQueueStatistics(adapterExtension,
                                              DispatchContext,
                                              GuidIndex,
                                              InstanceIndex,
                                              InstanceCount,
                                              InstanceLengthArray,
                                              BufferAvail,
                                              Buffer,
                                              &sizeNeeded);

            break;
        }
    case VioScsiWmiExtendedInfo_GUID_INDEX: {
            sizeNeeded = sizeof(VioScsiExtendedInfo) - 1;
            if (BufferAvail < sizeNeeded)
            {
                status = SRB_STATUS_DATA_OVERRUN;
                break;
            }

            VioScsiReadExtendedData(Context,
                                    Buffer);
            *InstanceLengthArray = sizeNeeded;
            status = SRB_STATUS_SUCCESS;
            break;
        }
    case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX: {
            PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
            sizeNeeded = sizeof(MS_SM_AdapterInformationQuery);
            if (BufferAvail < sizeNeeded)
            {
                status = SRB_STATUS_DATA_OVERRUN;
                break;
            }

            memset(pOutBfr, 0, sizeNeeded);
            pOutBfr->UniqueAdapterId = adapterExtension->hba_id;
            pOutBfr->HBAStatus = HBA_STATUS_OK;
            pOutBfr->NumberOfPorts = 1;
            pOutBfr->VendorSpecificID = VENDORID | (PRODUCTID << 16);
            CopyWMIString(pOutBfr->Manufacturer, MANUFACTURER, sizeof(pOutBfr->Manufacturer));
//FIXME
//			CopyWMIString(pOutBfr->SerialNumber, adaptExt->ser_num ? adaptExt->ser_num : SERIALNUMBER, sizeof(pOutBfr->SerialNumber));
            CopyWMIString(pOutBfr->SerialNumber, SERIALNUMBER, sizeof(pOutBfr->SerialNumber));
            CopyWMIString(pOutBfr->Model, MODEL, sizeof(pOutBfr->Model));
            CopyWMIString(pOutBfr->ModelDescription, MODELDESCRIPTION, sizeof(pOutBfr->ModelDescription));
            CopyWMIString(pOutBfr->FirmwareVersion, FIRMWAREVERSION, sizeof(pOutBfr->FirmwareVersion));
            CopyWMIString(pOutBfr->DriverName, DRIVERNAME, sizeof(pOutBfr->DriverName));
            CopyWMIString(pOutBfr->HBASymbolicName, HBASYMBOLICNAME, sizeof(pOutBfr->HBASymbolicName));
            CopyWMIString(pOutBfr->RedundantFirmwareVersion, FIRMWAREVERSION, sizeof(pOutBfr->RedundantFirmwareVersion));
            CopyWMIString(pOutBfr->MfgDomain, MFRDOMAIN, sizeof(pOutBfr->MfgDomain));

            *InstanceLengthArray = sizeNeeded;
            status = SRB_STATUS_SUCCESS;
            break;
        }
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
        {
            break;
        }
    }
    ScsiPortWmiPostProcess(DispatchContext, status, sizeNeeded);

    return status;
}

static inline
VOID
CopyQueueStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN ULONG InstanceIdx,
    OUT PVOID Buffer)
/*+++

Routine Description:

Copies the statistics for a virtqueue to the given destination.

--*/
{
    VirtQueue_Statistics* stats = (VirtQueue_Statistics*)Buffer;
    stats->TotalRequests = AdapterExtension->QueueStats[InstanceIdx].TotalRequests;
    stats->InFlightRequests = AdapterExtension->QueueStats[InstanceIdx].TotalRequests -
        AdapterExtension->QueueStats[InstanceIdx].CompletedRequests;
    stats->TotalKicks = AdapterExtension->QueueStats[InstanceIdx].TotalKicks;
    stats->SkippedKicks = AdapterExtension->QueueStats[InstanceIdx].SkippedKicks;
    stats->TotalInterrupts = AdapterExtension->QueueStats[InstanceIdx].TotalInterrupts;
    stats->LastUsedIdx = virtqueue_get_last_used_idx(AdapterExtension->vq[InstanceIdx + VIRTIO_SCSI_REQUEST_QUEUE_0]);
    stats->UsedIdx = virtqueue_get_used_idx(AdapterExtension->vq[InstanceIdx + VIRTIO_SCSI_REQUEST_QUEUE_0]);
    stats->QueueFullEvents = AdapterExtension->QueueStats[InstanceIdx].QueueFullEvents;
    stats->MaxLatency = AdapterExtension->QueueStats[InstanceIdx].MaxLatency;
    stats->BusyRequests = AdapterExtension->QueueStats[InstanceIdx].BusyRequests;
    stats->MaxIoDelay = AdapterExtension->QueueStats[InstanceIdx].MaxStartIoDelay;
    // We want max latency tracked since the last perfmon query.
    AdapterExtension->QueueStats[InstanceIdx].MaxLatency = 0;
    AdapterExtension->QueueStats[InstanceIdx].MaxStartIoDelay = 0;
}

WCHAR InstancePrefix[] = L"Adapter";
#define ADAPTER_DIGITS 4
#define INSTANCE_DIGITS 3

static USHORT powers_of_10[] = { 1, 10, 100, 1000, 10000 };

// These utility methods are needed because we
// can't call RtlStringCbPrintf at DISPATCH_LEVEL
VOID
AppendNumber(LPWSTR Destination, USHORT Number, UCHAR Digits) {
    int i;
    NT_ASSERT(Digits < 6);
    for (i = Digits; i > 0; i--) {
        *Destination = (Number / powers_of_10[i - 1]) + '0';
        Number = Number % powers_of_10[i - 1];
        Destination++;
    }
}

USHORT ExtractNumber(LPWSTR Destination, UCHAR Digits) {
    int i;
    USHORT result = 0;
    NT_ASSERT(Digits < 6);
    for (i = Digits; i > 0; i--) {
        NT_ASSERT(*Destination >= '0' && *Destination < '9');
        result += (*Destination - '0') * powers_of_10[i - 1];
        Destination++;
    }
    return result;
}

USHORT
GetPortNumber(IN PADAPTER_EXTENSION AdapterExtension) {
#if (NTDDI_VERSION >= NTDDI_WIN8)
    STOR_ADDR_BTL8 stor_addr = {
        STOR_ADDRESS_TYPE_BTL8,
        0,
        STOR_ADDR_BTL8_ADDRESS_LENGTH,
        0,
        0,
        0,
        0 };
    ULONG status = StorPortGetSystemPortNumber(AdapterExtension, (PSTOR_ADDRESS)&stor_addr);
    NT_ASSERT(status == STOR_STATUS_SUCCESS);
    return stor_addr.Port;
#else
    return AdapterExtension->PortNumber;
#endif
}

VOID
BuildInstanceName(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PCWSTR BaseName,
    IN USHORT BaseNameCchLen,
    IN UCHAR InstanceIdx,
    OUT PWMIString Name)
/*+++

Routine Description:

Returns the performance counter instance name for a given counter.
--*/
{
    USHORT len = _ARRAYSIZE(InstancePrefix) - 1;
    RtlCopyMemory(Name->Buffer, InstancePrefix, len * sizeof(WCHAR));
    AppendNumber(Name->Buffer + len, GetPortNumber(AdapterExtension), ADAPTER_DIGITS);
    len += ADAPTER_DIGITS;
    RtlCopyMemory(Name->Buffer + len, BaseName, BaseNameCchLen * sizeof(WCHAR));
    len += BaseNameCchLen;
    AppendNumber(Name->Buffer + len, InstanceIdx, INSTANCE_DIGITS);
    len += INSTANCE_DIGITS;
    Name->Buffer[len] = 0;
    Name->Length = len * sizeof(WCHAR);
}

UCHAR
GetInstanceIdx(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PCWSTR BaseName,
    IN USHORT BaseNameCchLen,
    IN PWMIString Name)
/*+++

Routine Description:

Given a instance name, returns the virtqueue whose these counters belong to.
Returns -1 if no instance is found.
--*/
{
    NT_ASSERT(BaseNameCchLen >= 1);
    int len = _ARRAYSIZE(InstancePrefix) - 1 + ADAPTER_DIGITS + BaseNameCchLen;
    if ((len + INSTANCE_DIGITS) * sizeof(WCHAR) == Name->Length &&
        Name->Buffer[len - 1] == BaseName[BaseNameCchLen - 1] &&
        Name->Buffer[len - BaseNameCchLen] == BaseName[0]) {
        return (UCHAR)ExtractNumber(Name->Buffer + len, INSTANCE_DIGITS);
    }

    NT_ASSERT(FALSE);
    return -1;
}

WCHAR VQBASENAME[] = L"Queue";

UCHAR
BuildVirtQueueStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer,
    OUT PULONG SizeNeeded
    )
/*+++

Routine Description:

Build queue statistics WMI data for all IO queues. Admin and event queues are not included.
--*/
{
    PWCHAR NameOffset;
    WMIString DynamicInstanceName;
    PUCHAR currentDataPos;
    UCHAR instanceIdx;
    PWMIString instanceName;
    ULONG newOutBufferAvail;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    *SizeNeeded = 0;

    if (DispatchContext->MinorFunction == IRP_MN_QUERY_ALL_DATA) {
        if (ScsiPortWmiSetInstanceCount(DispatchContext,
                                        AdapterExtension->num_queues,
                                        &newOutBufferAvail,
                                        SizeNeeded)) {
            if (newOutBufferAvail == 0) {
                srbStatus = SRB_STATUS_DATA_OVERRUN;
            }
            // WMI packs the results in a WNODE_ALL_DATA structure.
            // Even if we cannot copy the data, we still have to go through the loop to calculate
            // how much space is actually needed.
            for (instanceIdx = 0; instanceIdx < AdapterExtension->num_queues; instanceIdx++) {
                currentDataPos = (PUCHAR)ScsiPortWmiSetData(DispatchContext,
                    instanceIdx,
                    sizeof(VirtQueue_Statistics),
                    &newOutBufferAvail,
                    SizeNeeded);
                if (newOutBufferAvail == 0 || currentDataPos == NULL ||
                    currentDataPos + sizeof(VirtQueue_Statistics) > Buffer + BufferAvail) {
                    srbStatus = SRB_STATUS_DATA_OVERRUN;
                }
                if (srbStatus == SRB_STATUS_SUCCESS) {
                    CopyQueueStatistics(AdapterExtension, instanceIdx, currentDataPos);
                }
                BuildInstanceName(
                    AdapterExtension,
                    VQBASENAME,
                    _ARRAYSIZE(VQBASENAME) - 1,
                    instanceIdx,
                    &DynamicInstanceName);
                NameOffset = ScsiPortWmiSetInstanceName(
                    DispatchContext,
                    instanceIdx,
                    DynamicInstanceName.Length + sizeof(USHORT),
                    &newOutBufferAvail,
                    SizeNeeded);
                if (newOutBufferAvail == 0 || NameOffset == NULL ||
                    (PUCHAR)NameOffset + DynamicInstanceName.Length + sizeof(USHORT) > Buffer + BufferAvail) {
                    srbStatus = SRB_STATUS_DATA_OVERRUN;
                }
                if (srbStatus == SRB_STATUS_SUCCESS) {
                    RtlCopyMemory(NameOffset, (PUCHAR)(&DynamicInstanceName),
                        (DynamicInstanceName.Length + sizeof(USHORT)));
                }
            }
       } else {
           srbStatus = SRB_STATUS_ERROR;
       }
    } else {
        // single instance
        instanceName = (PWMIString)ScsiPortWmiGetInstanceName(DispatchContext);
        if (instanceName != NULL)
        {
            instanceIdx = GetInstanceIdx(AdapterExtension, VQBASENAME, _ARRAYSIZE(VQBASENAME) - 1, instanceName);
            *SizeNeeded = sizeof(VirtQueue_Statistics);
            if (BufferAvail >= *SizeNeeded && instanceIdx < AdapterExtension->num_queues) {
                CopyQueueStatistics(AdapterExtension, instanceIdx, Buffer);
                *InstanceLengthArray = *SizeNeeded;
            } else {
                // The buffer passed to return the data is too small
                srbStatus = SRB_STATUS_DATA_OVERRUN;
            }
        } else {
            srbStatus = SRB_STATUS_ERROR;
        }
    }

    return srbStatus;
}

VOID
VioScsiReadExtendedData(
    IN PVOID Context,
    OUT PUCHAR Buffer
    )
{
    UCHAR numberOfBytes = sizeof(VioScsiExtendedInfo) - 1;
    PADAPTER_EXTENSION    adaptExt;
    PVioScsiExtendedInfo  extInfo;

    adaptExt = (PADAPTER_EXTENSION)Context;
    extInfo = (PVioScsiExtendedInfo)Buffer;

    memset(Buffer, 0, numberOfBytes);

    extInfo->QueueDepth = (ULONG)adaptExt->queue_depth;
    extInfo->QueuesCount = (UCHAR)adaptExt->num_queues;
    extInfo->Indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);
    extInfo->EventIndex = CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX);
    extInfo->DpcRedirection = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_DPC_REDIRECTION);
    extInfo->ConcurentChannels = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_CONCURRENT_CHANNELS);
    extInfo->InterruptMsgRanges = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_INTERRUPT_MESSAGE_RANGES);
    extInfo->CompletionDuringStartIo = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO);
}

BOOLEAN
VioScsiPdoQueryWmiDataBlock(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer
    )
/*+++

Routine Description :

Called to query WMI Data blocks

--*/
{
    UCHAR status = SRB_STATUS_ERROR;
    ULONG sizeNeeded = 0;
    PADAPTER_EXTENSION adapterExtension = (PADAPTER_EXTENSION)Context;

    switch (GuidIndex) {
        case TargetStatistics_GUID_INDEX: {
            status = BuildTargetStatistics(adapterExtension,
                DispatchContext,
                GuidIndex,
                InstanceIndex,
                InstanceCount,
                InstanceLengthArray,
                BufferAvail,
                Buffer,
                &sizeNeeded);

            break;
        }
    }
    ScsiPortWmiPostProcess(DispatchContext, status, sizeNeeded);

    return status;
}

static inline
VOID
CopyTargetStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN ULONG InstanceIdx,
    OUT PVOID Buffer)
/*+++

Routine Description:

Copies the statistics for a scsi target to the given destination.

--*/
{
    Target_Statistics* stats = (Target_Statistics*)Buffer;
    stats->TotalRequests = AdapterExtension->TargetStats[InstanceIdx].TotalRequests;
    stats->InFlightRequests = AdapterExtension->TargetStats[InstanceIdx].TotalRequests -
        AdapterExtension->TargetStats[InstanceIdx].CompletedRequests;
    stats->ResetRequests = AdapterExtension->TargetStats[InstanceIdx].ResetRequests;
    stats->MaxLatency = AdapterExtension->TargetStats[InstanceIdx].MaxLatency;
    stats->BusyRequests = AdapterExtension->TargetStats[InstanceIdx].BusyRequests;
    // We want max latency tracked since the last perfmon query.
    AdapterExtension->TargetStats[InstanceIdx].MaxLatency = 0;
}

WCHAR TARGETBASENAME[] = L"Target";

UCHAR
BuildTargetStatistics(
    IN PADAPTER_EXTENSION AdapterExtension,
    IN PSCSIWMI_REQUEST_CONTEXT DispatchContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG InstanceCount,
    IN OUT PULONG InstanceLengthArray,
    IN ULONG BufferAvail,
    OUT PUCHAR Buffer,
    OUT PULONG SizeNeeded
    )
/*+++

Routine Description:

Build Target statistics WMI data for all Targets we saw so far.
--*/
{
    PWCHAR NameOffset;
    WMIString DynamicInstanceName;
    PUCHAR currentDataPos;
    UCHAR instanceIdx;
    PWMIString instanceName;
    ULONG newOutBufferAvail;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    *SizeNeeded = 0;

    if (DispatchContext->MinorFunction == IRP_MN_QUERY_ALL_DATA) {
        if (ScsiPortWmiSetInstanceCount(DispatchContext,
                                        AdapterExtension->MaxTarget,
                                        &newOutBufferAvail,
                                        SizeNeeded)) {
            if (newOutBufferAvail == 0) {
                srbStatus = SRB_STATUS_DATA_OVERRUN;
            }
            // WMI packs the results in a WNODE_ALL_DATA structure.
            // Even if we cannot copy the data, we still have to go through the loop to calculate
            // how much space is actually needed.
            for (instanceIdx = 0; instanceIdx < AdapterExtension->MaxTarget; instanceIdx++) {
                currentDataPos = (PUCHAR)ScsiPortWmiSetData(DispatchContext,
                    instanceIdx,
                    sizeof(Target_Statistics),
                    &newOutBufferAvail,
                    SizeNeeded);
                if (newOutBufferAvail == 0 || currentDataPos == NULL ||
                    currentDataPos + sizeof(Target_Statistics) > Buffer + BufferAvail) {
                    srbStatus = SRB_STATUS_DATA_OVERRUN;
                }
                if (srbStatus == SRB_STATUS_SUCCESS) {
                    CopyTargetStatistics(AdapterExtension, instanceIdx, currentDataPos);
                }
                BuildInstanceName(
                    AdapterExtension,
                    TARGETBASENAME,
                    _ARRAYSIZE(TARGETBASENAME) - 1,
                    instanceIdx,
                    &DynamicInstanceName);
                NameOffset = ScsiPortWmiSetInstanceName(
                    DispatchContext,
                    instanceIdx,
                    DynamicInstanceName.Length + sizeof(USHORT),
                    &newOutBufferAvail,
                    SizeNeeded);
                if (newOutBufferAvail == 0 || NameOffset == NULL ||
                    (PUCHAR)NameOffset + DynamicInstanceName.Length + sizeof(USHORT) > Buffer + BufferAvail) {
                    srbStatus = SRB_STATUS_DATA_OVERRUN;
                }
                if (srbStatus == SRB_STATUS_SUCCESS) {
                    RtlCopyMemory(NameOffset, (PUCHAR)(&DynamicInstanceName),
                            (DynamicInstanceName.Length + sizeof(USHORT)));
                }
            }
        } else {
           srbStatus = SRB_STATUS_ERROR;
       }
    } else {
        // single instance
        instanceName = (PWMIString)ScsiPortWmiGetInstanceName(DispatchContext);
        if (instanceName != NULL)
        {
            instanceIdx = GetInstanceIdx(AdapterExtension, TARGETBASENAME, _ARRAYSIZE(TARGETBASENAME) - 1, instanceName);
            *SizeNeeded = sizeof(Target_Statistics);
            if (BufferAvail >= *SizeNeeded && instanceIdx < AdapterExtension->MaxTarget) {
                CopyTargetStatistics(AdapterExtension, instanceIdx, Buffer);
                *InstanceLengthArray = *SizeNeeded;
            } else {
                // The buffer passed to return the data is too small
                srbStatus = SRB_STATUS_DATA_OVERRUN;
            }
        } else {
            srbStatus = SRB_STATUS_ERROR;
        }
    }

    return srbStatus;
}

UCHAR
VioScsiExecuteWmiMethod(
    IN PVOID Context,
    IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
    IN ULONG GuidIndex,
    IN ULONG InstanceIndex,
    IN ULONG MethodId,
    IN ULONG InBufferSize,
    IN ULONG OutBufferSize,
    IN OUT PUCHAR Buffer
    )
{
    PADAPTER_EXTENSION      adaptExt = (PADAPTER_EXTENSION)Context;
    ULONG                   size = 0;
    UCHAR                   status = SRB_STATUS_SUCCESS;

    switch (GuidIndex)
    {
        case VIOSCSI_SETUP_GUID_INDEX:
        {
            break;
        }
        case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX:
        {
            PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
            break;
        }
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
        {
            switch (MethodId)
            {
                case SM_GetPortType:
                {
                    PSM_GetPortType_IN  pInBfr = (PSM_GetPortType_IN)Buffer;
                    PSM_GetPortType_OUT pOutBfr = (PSM_GetPortType_OUT)Buffer;

                    size = SM_GetPortType_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetPortType_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }
                case SM_GetAdapterPortAttributes:
                {
                    PSM_GetAdapterPortAttributes_IN  pInBfr = (PSM_GetAdapterPortAttributes_IN)Buffer;
                    PSM_GetAdapterPortAttributes_OUT pOutBfr = (PSM_GetAdapterPortAttributes_OUT)Buffer;

                    size = SM_GetAdapterPortAttributes_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetAdapterPortAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_GetDiscoveredPortAttributes:
                {
                    PSM_GetDiscoveredPortAttributes_IN  pInBfr = (PSM_GetDiscoveredPortAttributes_IN)Buffer;
                    PSM_GetDiscoveredPortAttributes_OUT pOutBfr = (PSM_GetDiscoveredPortAttributes_OUT)Buffer;

                    size = SM_GetDiscoveredPortAttributes_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetDiscoveredPortAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_GetPortAttributesByWWN:
                {
                    PSM_GetPortAttributesByWWN_IN  pInBfr = (PSM_GetPortAttributesByWWN_IN)Buffer;
                    PSM_GetPortAttributesByWWN_OUT pOutBfr = (PSM_GetPortAttributesByWWN_OUT)Buffer;

                    size = SM_GetPortAttributesByWWN_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetPortAttributesByWWN_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_GetProtocolStatistics:
                {
                    PSM_GetProtocolStatistics_IN  pInBfr = (PSM_GetProtocolStatistics_IN)Buffer;
                    PSM_GetProtocolStatistics_OUT pOutBfr = (PSM_GetProtocolStatistics_OUT)Buffer;

                    size = SM_GetProtocolStatistics_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetProtocolStatistics_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_GetPhyStatistics:
                {
                    PSM_GetPhyStatistics_IN  pInBfr = (PSM_GetPhyStatistics_IN)Buffer;
                    PSM_GetPhyStatistics_OUT pOutBfr = (PSM_GetPhyStatistics_OUT)Buffer;

                    //FIXME
                    size = FIELD_OFFSET(SM_GetPhyStatistics_OUT, PhyCounter) + sizeof(LONGLONG);
                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetPhyStatistics_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }


                case SM_GetFCPhyAttributes:
                {
                    PSM_GetFCPhyAttributes_IN  pInBfr = (PSM_GetFCPhyAttributes_IN)Buffer;
                    PSM_GetFCPhyAttributes_OUT pOutBfr = (PSM_GetFCPhyAttributes_OUT)Buffer;

                    size = SM_GetFCPhyAttributes_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetFCPhyAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_GetSASPhyAttributes:
                {
                    PSM_GetSASPhyAttributes_IN  pInBfr = (PSM_GetSASPhyAttributes_IN)Buffer;
                    PSM_GetSASPhyAttributes_OUT pOutBfr = (PSM_GetSASPhyAttributes_OUT)Buffer;

                    size = SM_GetSASPhyAttributes_OUT_SIZE;

                    if (OutBufferSize < size)
                    {
                        status = SRB_STATUS_DATA_OVERRUN;
                        break;
                    }

                    if (InBufferSize < SM_GetSASPhyAttributes_IN_SIZE)
                    {
                        status = SRB_STATUS_BAD_FUNCTION;
                        break;
                    }

                    break;
                }

                case SM_RefreshInformation:
                {
                    break;
                }

                default:
                    status = SRB_STATUS_INVALID_REQUEST;
                    break;
            }
            default:
                status = SRB_STATUS_INVALID_REQUEST;

                break;
        }

    }
    ScsiPortWmiPostProcess(RequestContext,
        status,
        size);

    return SRB_STATUS_SUCCESS;

}
#endif
