//////////////////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2007  Qumranet All Rights Reserved
//
// Module Name:
// osdep.h
//
// Abstract:
// Windows OS dependent definitions of data types
//
// Author:
// Yan Vugenfirer  - February 2007.
//
//////////////////////////////////////////////////////////////////////////////////////////

#if defined(IGNORE_VIRTIO_OSDEP_H)
// to make simulation environment easy
#include "external_os_dep.h"
#else

#ifndef __OS_DEP_H
#define __OS_DEP_H

#include <ntddk.h>

#define ktime_t ULONGLONG
#define ktime_get() KeQueryPerformanceCounter(NULL).QuadPart

#define likely(x) x
#define unlikely(x) x

#define ENOSPC 1
#define BUG_ON(a) NT_ASSERT(!(a))
#define WARN_ON(a)
#define BUG() NT_ASSERT(0)

#if !defined(__cplusplus) && !defined(bool)
// Important note: in MSFT C++ bool length is 1 bytes
// C++ does not define length of bool
// inconsistent definition of 'bool' may create compatibility problems
#define bool u8
#define false FALSE
#define true TRUE
#endif
#endif

#ifndef INLINE_DEFINED
#define inline __forceinline
#endif

#ifdef DBG
#define DEBUG
#endif

#define mb()   KeMemoryBarrier()
#define rmb()  KeMemoryBarrier()
#define wmb()  KeMemoryBarrier()

#define SMP_CACHE_BYTES 64

#endif
