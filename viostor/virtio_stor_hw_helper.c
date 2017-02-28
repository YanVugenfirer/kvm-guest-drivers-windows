/**********************************************************************
 * Copyright (c) 2008-2016 Red Hat, Inc.
 *
 * File: virtio_stor_hw_helper.c
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
#include "virtio_stor_hw_helper.h"
#include"virtio_stor_utils.h"


#if (INDIRECT_SUPPORTED)
#define SET_VA_PA() { ULONG len; va = adaptExt->indirect ? srbExt->desc : NULL; \
                      pa = va ? ScsiPortGetPhysicalAddress(DeviceExtension, NULL, va, &len).QuadPart : 0; \
                    }
#else
#define SET_VA_PA()    va = NULL; pa = 0;
#endif


BOOLEAN
SynchronizedFlushRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE           Srb      = (PSRB_TYPE) Context;
    PSRB_EXTENSION srbExt        = SRB_EXTENSION(Srb);
    ULONG               fragLen;
    PVOID               va;
    ULONGLONG           pa;

    SET_VA_PA();

    srbExt->vbr.out_hdr.sector = 0;
    srbExt->vbr.out_hdr.ioprio = 0;
    srbExt->vbr.req            = (struct request *)Srb;
    srbExt->vbr.out_hdr.type   = VIRTIO_BLK_T_FLUSH;
    srbExt->out                = 1;
    srbExt->in                 = 1;

    srbExt->vbr.sg[0].physAddr = ScsiPortGetPhysicalAddress(DeviceExtension, NULL, &srbExt->vbr.out_hdr, &fragLen);
    srbExt->vbr.sg[0].length   = sizeof(srbExt->vbr.out_hdr);
    srbExt->vbr.sg[1].physAddr = ScsiPortGetPhysicalAddress(DeviceExtension, NULL, &srbExt->vbr.status, &fragLen);
    srbExt->vbr.sg[1].length   = sizeof(srbExt->vbr.status);

    if (virtqueue_add_buf(adaptExt->vq,
                     &srbExt->vbr.sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->vbr, va, pa) >= 0) {
           virtqueue_kick(adaptExt->vq);
        return TRUE;
    }
    virtqueue_kick(adaptExt->vq);
#ifdef USE_STORPORT
    StorPortBusy(DeviceExtension, 2);
#endif
    return FALSE;
}

#ifdef USE_STORPORT
BOOLEAN
RhelDoFlush(
    PVOID DeviceExtension,
    PSRB_TYPE Srb,
    BOOLEAN sync
    )
{
    if (sync) {
       return StorPortSynchronizeAccess(DeviceExtension, SynchronizedFlushRoutine, Srb);
    } else {
       return SynchronizedFlushRoutine(DeviceExtension, Srb);
    }
}
#else
BOOLEAN
RhelDoFlush(
    PVOID DeviceExtension,
    PSRB_TYPE Srb,
    BOOLEAN sync
    )
{
    UNREFERENCED_PARAMETER(sync);
    return SynchronizedFlushRoutine(DeviceExtension, Srb);
}
#endif

#ifdef USE_STORPORT
BOOLEAN
SynchronizedReadWriteRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE           Srb      = (PSRB_TYPE) Context;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va;
    ULONGLONG           pa;

    SET_VA_PA();

    if (virtqueue_add_buf(adaptExt->vq,
                     &srbExt->vbr.sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->vbr, va, pa) >= 0){
        InsertTailList(&adaptExt->list_head, &srbExt->vbr.list_entry);
           virtqueue_kick(adaptExt->vq);
        return TRUE;
    }
    virtqueue_kick(adaptExt->vq);
    StorPortBusy(DeviceExtension, 2);
    return FALSE;
}

BOOLEAN
RhelDoReadWrite(PVOID DeviceExtension,
                PSRB_TYPE Srb)
{
    return StorPortSynchronizeAccess(DeviceExtension, SynchronizedReadWriteRoutine, (PVOID)Srb);
}
#else
BOOLEAN
RhelDoReadWrite(PVOID DeviceExtension,
                PSRB_TYPE Srb)
{
    PCDB                  cdb;
    ULONG                 fragLen;
    ULONG                 sgElement;
    ULONG                 BytesLeft;
    PVOID                 DataBuffer;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
    int                   num_free;
    PVOID                 va;
    ULONGLONG             pa;
    ULONG                 i;
    ULONG                 sgMaxElements;

    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BytesLeft  = SRB_DATA_TRANSFER_LENGTH(Srb);
    DataBuffer = SRB_DATA_BUFFER(Srb);

    memset(srbExt, 0, sizeof (SRB_EXTENSION));
    sgMaxElements = MAX_PHYS_SEGMENTS + 1;
    for (i = 0, sgElement = 1; (i < sgMaxElements) && BytesLeft; i++, sgElement++) {
        srbExt->vbr.sg[sgElement].physAddr = ScsiPortGetPhysicalAddress(DeviceExtension, Srb, DataBuffer, &fragLen);
        srbExt->vbr.sg[sgElement].length   = fragLen;
        srbExt->Xfer += fragLen;
        BytesLeft -= fragLen;
        DataBuffer = (PVOID)((ULONG_PTR)DataBuffer + fragLen);
    }

    srbExt->vbr.out_hdr.sector = RhelGetLba(DeviceExtension, cdb);
    srbExt->vbr.out_hdr.ioprio = 0;
    srbExt->vbr.req            = (struct request *)Srb;

    if (SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) {
        srbExt->vbr.out_hdr.type = VIRTIO_BLK_T_OUT;
        srbExt->out = sgElement;
        srbExt->in = 1;
    } else {
        srbExt->vbr.out_hdr.type = VIRTIO_BLK_T_IN;
        srbExt->out = 1;
        srbExt->in = sgElement;
    }

    srbExt->vbr.sg[0].physAddr = ScsiPortGetPhysicalAddress(DeviceExtension, NULL, &srbExt->vbr.out_hdr, &fragLen);
    srbExt->vbr.sg[0].length = sizeof(srbExt->vbr.out_hdr);

    srbExt->vbr.sg[sgElement].physAddr = ScsiPortGetPhysicalAddress(DeviceExtension, NULL, &srbExt->vbr.status, &fragLen);
    srbExt->vbr.sg[sgElement].length = sizeof(srbExt->vbr.status);

    SET_VA_PA();
    num_free = virtqueue_add_buf(adaptExt->vq,
                                      &srbExt->vbr.sg[0],
                                      srbExt->out, srbExt->in,
                                      &srbExt->vbr, va, pa);

    if ( num_free >= 0) {
        InsertTailList(&adaptExt->list_head, &srbExt->vbr.list_entry);
        virtqueue_kick(adaptExt->vq);
        srbExt->call_next = FALSE;
        if(!adaptExt->indirect && num_free < VIRTIO_MAX_SG) {
            srbExt->call_next = TRUE;
        } else {
           ScsiPortNotification(NextLuRequest, DeviceExtension, SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb));
        }
    }
    return TRUE;
}
#endif

VOID
RhelShutDown(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    virtio_device_reset(&adaptExt->vdev);
    virtio_delete_queues(&adaptExt->vdev);
    virtio_device_shutdown(&adaptExt->vdev);
    adaptExt->vq = NULL;
}

ULONGLONG
RhelGetLba(
    IN PVOID DeviceExtension,
    IN PCDB Cdb
    )
{

    EIGHT_BYTE lba;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    lba.AsULongLong = 0;

    switch (Cdb->CDB6GENERIC.OperationCode) {

        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_WRITE_VERIFY: {
            lba.Byte0 = Cdb->CDB10.LogicalBlockByte3;
            lba.Byte1 = Cdb->CDB10.LogicalBlockByte2;
            lba.Byte2 = Cdb->CDB10.LogicalBlockByte1;
            lba.Byte3 = Cdb->CDB10.LogicalBlockByte0;
        }
        break;
        case SCSIOP_READ6:
        case SCSIOP_WRITE6: {
            lba.Byte0 = Cdb->CDB6READWRITE.LogicalBlockMsb1;
            lba.Byte1 = Cdb->CDB6READWRITE.LogicalBlockMsb0;
            lba.Byte2 = Cdb->CDB6READWRITE.LogicalBlockLsb;
        }
        break;
        case SCSIOP_READ12:
        case SCSIOP_WRITE12:
        case SCSIOP_WRITE_VERIFY12: {
            REVERSE_BYTES(&lba, &Cdb->CDB12.LogicalBlock[0]);
        }
        break;
        case SCSIOP_READ16:
        case SCSIOP_WRITE16:
        case SCSIOP_READ_CAPACITY16:
        case SCSIOP_WRITE_VERIFY16: {
            REVERSE_BYTES_QUAD(&lba, &Cdb->CDB16.LogicalBlock[0]);
        }
        break;
        default: {
            ASSERT(FALSE);
            return (ULONGLONG)-1;
        }
    }
    return (lba.AsULongLong * (adaptExt->info.blk_size / SECTOR_SIZE));
}

VOID
RhelGetSerialNumber(
    IN PVOID DeviceExtension
)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    adaptExt->vbr.out_hdr.type = VIRTIO_BLK_T_GET_ID | VIRTIO_BLK_T_IN;
    adaptExt->vbr.out_hdr.sector = 0;
    adaptExt->vbr.out_hdr.ioprio = 0;

    adaptExt->vbr.sg[0].physAddr = MmGetPhysicalAddress(&adaptExt->vbr.out_hdr);
    adaptExt->vbr.sg[0].length   = sizeof(adaptExt->vbr.out_hdr);
    adaptExt->vbr.sg[1].physAddr = MmGetPhysicalAddress(&adaptExt->sn);
    adaptExt->vbr.sg[1].length   = sizeof(adaptExt->sn);
    adaptExt->vbr.sg[2].physAddr = MmGetPhysicalAddress(&adaptExt->vbr.status);
    adaptExt->vbr.sg[2].length   = sizeof(adaptExt->vbr.status);

    if (virtqueue_add_buf(adaptExt->vq,
                     &adaptExt->vbr.sg[0],
                     1, 2,
                     &adaptExt->vbr, NULL, 0) >= 0) {
        virtqueue_kick(adaptExt->vq);
    }
}

VOID
RhelGetDiskGeometry(
    IN PVOID DeviceExtension
)
{
    u64                cap;
    u32                v;
    struct virtio_blk_geometry vgeo;

    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    adaptExt->features = virtio_get_features(&adaptExt->vdev);

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_BARRIER)) {
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("VIRTIO_BLK_F_BARRIER\n"));
    }

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_RO)) {
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("VIRTIO_BLK_F_RO\n"));
    }

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_SIZE_MAX)) {
        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, size_max),
                          &v, sizeof(v));
        adaptExt->info.size_max = v;
    } else {
        adaptExt->info.size_max = SECTOR_SIZE;
    }

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_SEG_MAX)) {
        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, seg_max),
                          &v, sizeof(v));
        adaptExt->info.seg_max = v;
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("VIRTIO_BLK_F_SEG_MAX = %d\n", adaptExt->info.seg_max));
    }

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_BLK_SIZE)) {
        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, blk_size),
                          &v, sizeof(v));
        adaptExt->info.blk_size = v;
    } else {
        adaptExt->info.blk_size = SECTOR_SIZE;
    }
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("VIRTIO_BLK_F_BLK_SIZE = %d\n", adaptExt->info.blk_size));

    if (CHECKBIT(adaptExt->features, VIRTIO_BLK_F_GEOMETRY)) {
        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, geometry),
                          &vgeo, sizeof(vgeo));
        adaptExt->info.geometry.cylinders= vgeo.cylinders;
        adaptExt->info.geometry.heads    = vgeo.heads;
        adaptExt->info.geometry.sectors  = vgeo.sectors;
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("VIRTIO_BLK_F_GEOMETRY. cylinders = %d  heads = %d  sectors = %d\n", adaptExt->info.geometry.cylinders, adaptExt->info.geometry.heads, adaptExt->info.geometry.sectors));
    }

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, capacity),
                      &cap, sizeof(cap));
    adaptExt->info.capacity = cap;
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("capacity = %08I64X\n", adaptExt->info.capacity));


    if(CHECKBIT(adaptExt->features, VIRTIO_BLK_F_TOPOLOGY)) {
        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, physical_block_exp),
                          &adaptExt->info.physical_block_exp, sizeof(adaptExt->info.physical_block_exp));
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("physical_block_exp = %d\n", adaptExt->info.physical_block_exp));

        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, alignment_offset),
                          &adaptExt->info.alignment_offset, sizeof(adaptExt->info.alignment_offset));
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("alignment_offset = %d\n", adaptExt->info.alignment_offset));

        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, min_io_size),
                          &adaptExt->info.min_io_size, sizeof(adaptExt->info.min_io_size));
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("min_io_size = %d\n", adaptExt->info.min_io_size));

        virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(blk_config, opt_io_size),
                          &adaptExt->info.opt_io_size, sizeof(adaptExt->info.opt_io_size));
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, ("opt_io_size = %d\n", adaptExt->info.opt_io_size));
    }
}
