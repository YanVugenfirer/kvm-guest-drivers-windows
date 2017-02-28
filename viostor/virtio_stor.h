/**********************************************************************
 * Copyright (c) 2008-2016 Red Hat, Inc.
 *
 * File: virtio_stor.h
 *
 * Main include file
 * This file contains vrious routines and globals
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/

#ifndef ___VIOSTOR_H__
#define ___VIOSTOR_H__

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
#include "virtio_ring.h"

typedef struct VirtIOBufferDescriptor VIO_SG, *PVIO_SG;

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER    0       /* Does host support barriers? */
#define VIRTIO_BLK_F_SIZE_MAX   1       /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX    2       /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY   4       /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO         5       /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE   6       /* Block size of disk is available*/
#define VIRTIO_BLK_F_SCSI       7       /* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH	9	/* Flush command supported */
#define VIRTIO_BLK_F_TOPOLOGY   10      /* Topology information is available */
#define VIRTIO_BLK_F_CONFIG_WCE	11	/* Writeback mode available in config */
#define VIRTIO_BLK_F_MQ		12	/* support more than one vq */

/* These two define direction. */
#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1

#define VIRTIO_BLK_T_SCSI_CMD   2
#define VIRTIO_BLK_T_FLUSH      4
#define VIRTIO_BLK_T_GET_ID     8

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

#define SECTOR_SIZE             512
#define IO_PORT_LENGTH          0x40

#define VIRTIO_RING_F_INDIRECT_DESC     28

#define BLOCK_SERIAL_STRLEN     20

#ifdef INDIRECT_SUPPORTED
#define MAX_PHYS_SEGMENTS       64
#else
#define MAX_PHYS_SEGMENTS       16
#endif

#define VIRTIO_MAX_SG           (3+MAX_PHYS_SEGMENTS)

#pragma pack(1)
typedef struct virtio_blk_config {
    /* The capacity (in 512-byte sectors). */
    u64 capacity;
    /* The maximum segment size (if VIRTIO_BLK_F_SIZE_MAX) */
    u32 size_max;
    /* The maximum number of segments (if VIRTIO_BLK_F_SEG_MAX) */
    u32 seg_max;
    /* geometry the device (if VIRTIO_BLK_F_GEOMETRY) */
    struct virtio_blk_geometry {
        u16 cylinders;
        u8 heads;
        u8 sectors;
    } geometry;
    /* block size of device (if VIRTIO_BLK_F_BLK_SIZE) */
    u32 blk_size;
    u8  physical_block_exp;
    u8  alignment_offset;
    u16 min_io_size;
    u32 opt_io_size;
    /* writeback mode (if VIRTIO_BLK_F_CONFIG_WCE) */
    u8 wce;
    u8 unused;
    /* number of vqs, only available when VIRTIO_BLK_F_MQ is set */
    u16 num_queues;
}blk_config, *pblk_config;
#pragma pack()

typedef struct virtio_blk_outhdr {
    /* VIRTIO_BLK_T* */
    u32 type;
    /* io priority. */
    u32 ioprio;
    /* Sector (ie. 512 byte offset) */
    u64 sector;
}blk_outhdr, *pblk_outhdr;

typedef struct virtio_blk_req {
    LIST_ENTRY list_entry;
    PVOID      req;
    blk_outhdr out_hdr;
    u8         status;
    VIO_SG     sg[VIRTIO_MAX_SG];
}blk_req, *pblk_req;

typedef struct virtio_bar {
    PHYSICAL_ADDRESS  BasePA;
    ULONG             uLength;
    PVOID             pBase;
    BOOLEAN           bPortSpace;
} VIRTIO_BAR, *PVIRTIO_BAR;

typedef struct _ADAPTER_EXTENSION {
    VirtIODevice          vdev;

    PVOID                 pageAllocationVa;
    ULONG                 pageAllocationSize;
    ULONG                 pageOffset;

    PVOID                 poolAllocationVa;
    ULONG                 poolAllocationSize;
    ULONG                 poolOffset;

    struct virtqueue *    vq;
    USHORT                num_queues;
    INQUIRYDATA           inquiry_data;
    blk_config            info;
    ULONG                 queue_depth;
    BOOLEAN               dump_mode;
    LIST_ENTRY            list_head;
    ULONG                 msix_vectors;
    BOOLEAN               msix_enabled;
    ULONGLONG             features;
    CHAR                  sn[BLOCK_SERIAL_STRLEN];
    BOOLEAN               sn_ok;
    blk_req               vbr;
    BOOLEAN               indirect;
    ULONGLONG             lastLBA;

    union {
        PCI_COMMON_HEADER pci_config;
        UCHAR             pci_config_buf[sizeof(PCI_COMMON_CONFIG)];
    };
    VIRTIO_BAR            pci_bars[PCI_TYPE0_ADDRESSES];
    ULONG                 system_io_bus_number;

#ifdef USE_STORPORT
    LIST_ENTRY            complete_list;
    STOR_DPC              completion_dpc;
    BOOLEAN               dpc_ok;
#endif
}ADAPTER_EXTENSION, *PADAPTER_EXTENSION;

#if (INDIRECT_SUPPORTED == 1)
typedef struct _VRING_DESC_ALIAS
{
    union
    {
        ULONGLONG data[2];
        UCHAR chars[SIZE_OF_SINGLE_INDIRECT_DESC];
    }u;
}VRING_DESC_ALIAS;
#endif

typedef struct _SRB_EXTENSION {
    blk_req               vbr;
    ULONG                 out;
    ULONG                 in;
    ULONG                 Xfer;
    BOOLEAN               fua;
#ifndef USE_STORPORT
    BOOLEAN               call_next;
#endif
#if INDIRECT_SUPPORTED
    VRING_DESC_ALIAS      desc[VIRTIO_MAX_SG];
#endif
}SRB_EXTENSION, *PSRB_EXTENSION;

BOOLEAN
VirtIoInterrupt(
    IN PVOID DeviceExtension
    );

#ifdef MSI_SUPPORTED
#ifndef PCIX_TABLE_POINTER
typedef struct {
  union {
    struct {
      ULONG BaseIndexRegister :3;
      ULONG Reserved          :29;
    };
    ULONG TableOffset;
  };
} PCIX_TABLE_POINTER, *PPCIX_TABLE_POINTER;
#endif

#ifndef PCI_MSIX_CAPABILITY
typedef struct {
  PCI_CAPABILITIES_HEADER Header;
  struct {
    USHORT TableSize      :11;
    USHORT Reserved       :3;
    USHORT FunctionMask   :1;
    USHORT MSIXEnable     :1;
  } MessageControl;
  PCIX_TABLE_POINTER      MessageTable;
  PCIX_TABLE_POINTER      PBATable;
} PCI_MSIX_CAPABILITY, *PPCI_MSIX_CAPABILITY;
#endif
#endif

#endif ___VIOSTOR__H__
