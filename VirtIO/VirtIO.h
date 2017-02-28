#ifndef _LINUX_VIRTIO_H
#define _LINUX_VIRTIO_H

#define scatterlist VirtIOBufferDescriptor

#ifndef VIRTIO_DEVICE_DEFINED
typedef struct TypeVirtIODevice VirtIODevice;
#endif
struct VirtIOBufferDescriptor {
    PHYSICAL_ADDRESS physAddr;
    ULONG length;
};

/**
 * virtqueue - a queue to register buffers for sending or receiving.
 * @vdev: the virtio device this queue was created for.
 * @priv: a pointer for the virtqueue implementation to use.
 * @index: the zero-based ordinal number for this queue.
 * @num_free: number of elements we expect to be able to fit.
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 */
struct virtqueue {
    VirtIODevice *vdev;
    unsigned int index;
    unsigned int num_free;
    void *priv;
};

int virtqueue_add_buf(struct virtqueue *vq,
                      struct scatterlist sg[],
                      unsigned int out_num,
                      unsigned int in_num,
                      void *data,
                      void *va_indirect,
                      ULONGLONG phys_indirect);

void virtqueue_kick(struct virtqueue *vq);

bool virtqueue_kick_prepare(struct virtqueue *vq);

void virtqueue_kick_always(struct virtqueue *vq);

void virtqueue_notify(struct virtqueue *vq);

void *virtqueue_get_buf(struct virtqueue *vq, unsigned int *len);

void virtqueue_disable_cb(struct virtqueue *vq);

bool virtqueue_enable_cb(struct virtqueue *vq);

bool virtqueue_enable_cb_delayed(struct virtqueue *vq);

void *virtqueue_detach_unused_buf(struct virtqueue *vq);

unsigned int virtqueue_get_vring_size(struct virtqueue *vq);

BOOLEAN virtqueue_is_interrupt_enabled(struct virtqueue *_vq);

BOOLEAN virtqueue_has_buf(struct virtqueue *_vq);

void virtqueue_shutdown(struct virtqueue *_vq);

u16 virtqueue_get_last_used_idx(struct virtqueue *_vq);

u16 virtqueue_get_used_idx(struct virtqueue *_vq);

#endif /* _LINUX_VIRTIO_H */
