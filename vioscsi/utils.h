/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: utils.h
 *
 *
 * This file contains debug print support routines and globals.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#ifndef ___UTILS_H___
#define ___UTILS_H___


#include <ntddk.h>
#include <storport.h>
#include <stdarg.h>
#include "kdebugprint.h"
#if defined(EVENT_TRACING)
#include "evntrace.h"
#endif

#define CHECKBIT(value, nbit) virtio_is_feature_enabled(value, nbit)
#define CHECKFLAG(value, flag) ((value & (flag)) == flag)
#define SETFLAG(value, flag) (value |= (flag))

#define CACHE_LINE_SIZE 64
#define ROUND_TO_CACHE_LINES(Size)  (((ULONG_PTR)(Size) + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1))

#if 0
#define CHECK_CPU(Srb) { \
    PROCESSOR_NUMBER    ProcNumber; \
    ULONG               processor = KeGetCurrentProcessorNumberEx(&ProcNumber); \
    PSRB_EXTENSION srbExt  = (PSRB_EXTENSION)Srb->SrbExtension; \
    if (ProcNumber.Group != srbExt->procNum.Group || \
        ProcNumber.Number != srbExt->procNum.Number) { \
           RhelDbgPrint(TRACE_LEVEL_ERROR, ("%s Srb %p issued on %d::%d currentn %d::%d\n", \
                   __FUNCTION__, Srb, srbExt->procNum.Group, srbExt->procNum.Number, ProcNumber.Group, ProcNumber.Number)); \
    } \
}while (0);

#else
#define CHECK_CPU(Srb)
#endif

void InitializeDriverOptions(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

extern int nViostorDebugLevel;
extern ULONG disabledPerfOptions;

#if defined(COM_DEBUG) || defined(PRINT_DEBUG) || defined(EVENT_TRACING)
#define ENABLE_TRACE
#endif

#ifdef ENABLE_TRACE
#define RhelDbgPrint(level, line) \
    if ((!bDebugPrint) || level > nViostorDebugLevel) {} \
    else VirtioDebugPrintProc line
#else
#define RhelDbgPrint(level, line)
#endif

typedef enum _VIOSCSI_ETW_EVENT_IDS {
    VioScsiEtwEventFunction = 0
} VIOSCSI_ETW_EVENT_IDS, *PVIOSCSI_ETW_EVENT_IDS;

char *DbgGetScsiOpStr(PSCSI_REQUEST_BLOCK Srb);

///////////////////
// DEBUG SUPPORT //
///////////////////

#ifndef TRACE_LEVEL_INFORMATION
#define TRACE_LEVEL_NONE        0   // Tracing is not on
#define TRACE_LEVEL_CRITICAL    1   // Abnormal exit or termination
#define TRACE_LEVEL_FATAL       1   // Deprecated name for Abnormal exit or termination
#define TRACE_LEVEL_ERROR       2   // Severe errors that need logging
#define TRACE_LEVEL_WARNING     3   // Warnings such as allocation failure
#define TRACE_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
#define TRACE_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
#define TRACE_LEVEL_RESERVED6   6
#define TRACE_LEVEL_RESERVED7   7
#define TRACE_LEVEL_RESERVED8   8
#define TRACE_LEVEL_RESERVED9   9
#endif // TRACE_LEVEL_INFORMATION

#ifndef DRIVER_START
#define DRIVER_START 0
#define DRIVER_STOP 1
#define DRIVER_IO 2
#endif // DRIVER_START

#ifdef EVENT_TRACING
#define WIDE2(x) L##x
#define WIDE(x) WIDE2(x)
#define FUNCTIONW WIDE(__FUNCTION__)

int FORCEINLINE OpToEtwOpcode(int Operation) {
    switch(Operation) {
    case DRIVER_START:
        return StorportEtwEventOpcodeStart;
    case DRIVER_STOP:
        return StorportEtwEventOpcodeStop;
    }
    return StorportEtwEventOpcodeInfo;
}

int FORCEINLINE OpToEtwKeywords(int Operation) {
    switch(Operation) {
    case DRIVER_START:
    case DRIVER_STOP:
        return STORPORT_ETW_EVENT_KEYWORD_ENUMERATION;
    }
    return STORPORT_ETW_EVENT_KEYWORD_IO;
}
#define TRACE_CONTEXT_NO_DEVICE_EXTENSION() PVOID DeviceExtension = NULL; PVOID Srb = NULL;
#define TRACE_CONTEXT_SET_DEVICE_EXTENSION(DEVEXT) PVOID DeviceExtension = DEVEXT; PVOID Srb = NULL;
#define TRACE_CONTEXT_NO_SRB() PVOID Srb = NULL;
#define ETW_ENTER_FN() StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, FUNCTIONW, \
                                     STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE,  StorportEtwLevelVerbose, \
                                     StorportEtwEventOpcodeInfo, NULL, L"-->", 1, NULL, 0)
#define ETW_ENTER_FN1(Param1, Value1) \
    StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, FUNCTIONW, \
                      STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE,  StorportEtwLevelVerbose, \
                      StorportEtwEventOpcodeInfo, NULL, L"-->", 1, WIDE(Param1), (ULONGLONG)(Value1))
#define ETW_EXIT_FN()  StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, FUNCTIONW, \
                                     STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE,  StorportEtwLevelVerbose, \
                                     StorportEtwEventOpcodeInfo, NULL, L"<--", 1, NULL, 0)
#define ETW_EXIT_ERR() StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, FUNCTIONW, \
                                     STORPORT_ETW_EVENT_KEYWORD_PERFORMANCE,  StorportEtwLevelVerbose, \
                                     StorportEtwEventOpcodeInfo, NULL, L"<--", 1, L"Line", __LINE__)
#define ETW_TRACE(Level, Operation, Message) \
    StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, NULL, 0, NULL, 0)
#define ETW_TRACE1(Level, Operation, Message, Param1, Value1) \
    StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), NULL, 0)
#define ETW_TRACE2(Level, Operation, Message, Param1, Value1, Param2, Value2) \
    StorPortEtwEvent2(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2))
#define ETW_TRACE3(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3) \
    StorPortEtwEvent4(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2), WIDE(Param3), (ULONGLONG)(Value3), \
                      NULL, 0)
#define ETW_TRACE4(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4) \
    StorPortEtwEvent4(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2), WIDE(Param3), (ULONGLONG)(Value3), \
                      WIDE(Param4), (ULONGLONG)(Value4))
#define ETW_TRACE5(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5) \
    StorPortEtwEvent8(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2), WIDE(Param3), (ULONGLONG)(Value3), \
                      WIDE(Param4), (ULONGLONG)(Value4), WIDE(Param5), (ULONGLONG)(Value5), \
                      NULL, 0, NULL, 0, NULL, 0)
#define ETW_TRACE6(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6) \
    StorPortEtwEvent8(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2), WIDE(Param3), (ULONGLONG)(Value3), \
                      WIDE(Param4), (ULONGLONG)(Value4), WIDE(Param5), (ULONGLONG)(Value5), \
                      WIDE(Param6), (ULONGLONG)(Value6), NULL, 0, NULL, 0)
#define ETW_TRACE7(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6, Param7, Value7) \
    StorPortEtwEvent8(DeviceExtension, NULL, VioScsiEtwEventFunction, WIDE(Message), \
                      OpToEtwKeywords(Operation),  Level, \
                      OpToEtwOpcode(Operation), (PSCSI_REQUEST_BLOCK)Srb, WIDE(Param1), (ULONGLONG)(Value1), \
                      WIDE(Param2), (ULONGLONG)(Value2), WIDE(Param3), (ULONGLONG)(Value3), \
                      WIDE(Param4), (ULONGLONG)(Value4), WIDE(Param5), (ULONGLONG)(Value5), \
                      WIDE(Param6), (ULONGLONG)(Value6), WIDE(Param7), (ULONGLONG)(Value7), \
                      NULL, 0)

#else
#define TRACE_CONTEXT_NO_DEVICE_EXTENSION()
#define TRACE_CONTEXT_SET_DEVICE_EXTENSION(DEVEXT)
#define TRACE_CONTEXT_NO_SRB()
#define ETW_ENTER_FN()
#define ETW_ENTER_FN1(Param1, Value1)
#define ETW_EXIT_FN()
#define ETW_EXIT_ERR()
#define ETW_TRACE(Level, Operation, Message)
#define ETW_TRACE1(Level, Operation, Message, Param1, Value1)
#define ETW_TRACE2(Level, Operation, Message, Param1, Value1, Param2, Value2)
#define ETW_TRACE3(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3)
#define ETW_TRACE4(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4)
#define ETW_TRACE5(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5)
#define ETW_TRACE6(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6)
#define ETW_TRACE7(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6, Param7, Value7)
#endif

#define ENTER_FN() ETW_ENTER_FN();RhelDbgPrint(TRACE_LEVEL_VERBOSE, (("--> %s.\n"),__FUNCTION__))
#define ENTER_FN1(Param1, Value1) ETW_ENTER_FN1(Param1, Value1);RhelDbgPrint(TRACE_LEVEL_VERBOSE, (("--> %s %s=0x%X.\n"),__FUNCTION__, Param1, Value1))
#define EXIT_FN()  ETW_EXIT_FN();RhelDbgPrint(TRACE_LEVEL_VERBOSE, (("<-- %s.\n"),__FUNCTION__))
#define EXIT_ERR() ETW_EXIT_ERR();RhelDbgPrint(TRACE_LEVEL_ERROR, (("<--> %s (%d).\n"), __FUNCTION__, __LINE__))
#define TRACE(Level, Operation, Message) \
    ETW_TRACE(Level, Operation, Message); \
    RhelDbgPrint(Level, ("%s\n", Message))
#define TRACE1(Level, Operation, Message, Param1, Value1) \
    ETW_TRACE1(Level, Operation, Message, Param1, Value1); \
    RhelDbgPrint(Level, ("%s %s=0x%X\n", Param1, Value1))
#define TRACE2(Level, Operation, Message, Param1, Value1, Param2, Value2) \
    ETW_TRACE2(Level, Operation, Message, Param1, Value1, Param2, Value2); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2))
#define TRACE3(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3) \
    ETW_TRACE3(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2, Param3, Value3))
#define TRACE4(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4) \
    ETW_TRACE4(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4))
#define TRACE5(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5) \
    ETW_TRACE5(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X %s=0x%X %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5))
#define TRACE6(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6) \
    ETW_TRACE6(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X %s=0x%X %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6))
#define TRACE7(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6, Param7, Value7) \
    ETW_TRACE7(Level, Operation, Message, Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6, Param7, Value7); \
    RhelDbgPrint(Level, ("%s %s=0x%X %s=0x%X %s=0x%X %s=0x%X %s=0x%X %s=0x%X %s=0x%X\n", Param1, Value1, Param2, Value2, Param3, Value3, Param4, Value4, Param5, Value5, Param6, Value6, Param7, Value7))

#endif // ___UTILS_H___

