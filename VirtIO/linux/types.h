#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#define __bitwise__
#ifndef __GNUC__
#define __attribute__(x)
#endif

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned long
#define u64 ULONGLONG

#define __u8 unsigned char
#define __u16 unsigned short
#define __le16 unsigned short
#define __u32 unsigned long
#define __le32 unsigned long
#define __u64 ULONGLONG

#endif /* _LINUX_TYPES_H */
