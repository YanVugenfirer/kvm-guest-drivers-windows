#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define TARGETOS 63
#elif (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define TARGETOS 62
#elif (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define TARGETOS 61
#elif (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define TARGETOS 60
#else
#define TARGETOS 50
#endif

#if defined(INCLUDE_CONFIG)

#if TARGETOS >= 61
#define PARANDIS_SUPPORT_RSS 1
#endif

#endif

#if TARGETOS == 61
#define _LargeQueueEntry
#endif

#if TARGETOS >= 60
#define _LsoV2IPv4
#define _LsoV2IPv6
#define _IPChecksumOffload
#define _UDPChecksumOffloadIPv4
#define _TCPChecksumOffloadIPv4
#define _UDPChecksumOffloadIPv6
#define _TCPChecksumOffloadIPv6
#endif

#if TARGETOS <= 51
#define DEFAULT_CONNECT_RATE    "1000"
#define DEFAULT_TX_CHECKSUM     "0"
#define DEFAULT_RX_CHECKSUM     "0"
#elif TARGETOS < 60
#define DEFAULT_CONNECT_RATE    "10000"
#define DEFAULT_TX_CHECKSUM     "27"
#define DEFAULT_RX_CHECKSUM     "0"
#else
#define DEFAULT_CONNECT_RATE    "10000"
#define DEFAULT_TX_CHECKSUM     "31"
#define DEFAULT_RX_CHECKSUM     "31"
#endif

#if TARGETOS >= 62
#define PARANDIS_SUPPORT_RSC 1
#define PARANDIS_SPECIFY_PORT_NUMBER 1
#endif

#if defined(INCLUDE_PARAMS)
HKR, Ndi\Params\ConnectRate,        ParamDesc,  0,          %ConnectRate%
HKR, Ndi\Params\ConnectRate,        Default,    0,          DEFAULT_CONNECT_RATE
HKR, Ndi\Params\ConnectRate,        type,       0,          "enum"
HKR, Ndi\Params\ConnectRate\enum,   "10",       0,          %10M%
HKR, Ndi\Params\ConnectRate\enum,   "100",      0,          %100M%
HKR, Ndi\Params\ConnectRate\enum,   "1000",     0,          %1G%
HKR, Ndi\Params\ConnectRate\enum,   "10000",    0,          %10G%

HKR, Ndi\Params\Priority,           ParamDesc,  0,          %Priority%
HKR, Ndi\Params\Priority,           Default,    0,          "1"
HKR, Ndi\Params\Priority,           type,       0,          "enum"
HKR, Ndi\Params\Priority\enum,      "1",        0,          %Enable%
HKR, Ndi\Params\Priority\enum,      "0",        0,          %Disable%

HKR, Ndi\Params\*PriorityVLANTag,           ParamDesc,  0,          %PriorityVlanTag%
HKR, Ndi\Params\*PriorityVLANTag,           Default,    0,          "3"
HKR, Ndi\Params\*PriorityVLANTag,           type,       0,          "enum"
HKR, Ndi\Params\*PriorityVLANTag\enum,      "3",        0,          %Priority_Vlan%
HKR, Ndi\Params\*PriorityVLANTag\enum,      "2",        0,          %VLan%
HKR, Ndi\Params\*PriorityVLANTag\enum,      "1",        0,          %PriorityOnly%
HKR, Ndi\Params\*PriorityVLANTag\enum,      "0",        0,          %Disable%

#if defined(PARANDIS_SUPPORT_RSS)
HKR, Ndi\params\*RSS,              ParamDesc,   0,          %Rss%
HKR, Ndi\params\*RSS,              Default,     0,          "1"
HKR, Ndi\params\*RSS,              type,        0,          "enum"
HKR, Ndi\params\*RSS,              Optional,    0,          "0"
HKR, Ndi\params\*RSS\enum,         "1",         0,          %Enable%
HKR, Ndi\params\*RSS\enum,         "0",         0,          %Disable%

HKR, Ndi\params\*NumRssQueues,      ParamDesc,  0,          %MaxRssQueues%
HKR, Ndi\params\*NumRssQueues,      default,    0,          "8"
HKR, Ndi\params\*NumRssQueues,      type,       0,          "int"
HKR, Ndi\params\*NumRssQueues,      min,        0,          "1"
HKR, Ndi\params\*NumRssQueues,      max,        0,          "16"
HKR, Ndi\params\*NumRssQueues,      step,       0,          "1"
#endif

#if defined(PARANDIS_SUPPORT_RSC)
HKR, Ndi\Params\*RscIPv4,           ParamDesc,  0,          %RscIPv4%
HKR, Ndi\Params\*RscIPv4,           Default,    0,          "1"
HKR, Ndi\Params\*RscIPv4,           type,       0,          "enum"
HKR, Ndi\Params\*RscIPv4\enum,      "1",        0,          %Enable%
HKR, Ndi\Params\*RscIPv4\enum,      "0",        0,          %Disable%

HKR, Ndi\Params\*RscIPv6,           ParamDesc,  0,          %RscIPv6%
HKR, Ndi\Params\*RscIPv6,           Default,    0,          "1"
HKR, Ndi\Params\*RscIPv6,           type,       0,          "enum"
HKR, Ndi\Params\*RscIPv6\enum,      "1",        0,          %Enable%
HKR, Ndi\Params\*RscIPv6\enum,      "0",        0,          %Disable%
#endif

HKR, Ndi\Params\DoLog,              ParamDesc,  0,          %EnableLogging%
HKR, Ndi\Params\DoLog,              Default,    0,          "1"
HKR, Ndi\Params\DoLog,              type,       0,          "enum"
HKR, Ndi\Params\DoLog\enum,         "1",        0,          %Enable%
HKR, Ndi\Params\DoLog\enum,         "0",        0,          %Disable%

HKR, Ndi\params\DebugLevel,         ParamDesc,  0,          %DebugLevel%
HKR, Ndi\params\DebugLevel,         type,       0,          "int"
HKR, Ndi\params\DebugLevel,         default,    0,          "0"
HKR, Ndi\params\DebugLevel,         min,        0,          "0"
HKR, Ndi\params\DebugLevel,         max,        0,          "8"
HKR, Ndi\params\DebugLevel,         step,       0,          "1"

HKR, Ndi\params\MTU,                ParamDesc,  0,          %MTU%
HKR, Ndi\params\MTU,                type,       0,          "long"
HKR, Ndi\params\MTU,                default,    0,          "1500"
HKR, Ndi\params\MTU,                min,        0,          "576"
HKR, Ndi\params\MTU,                max,        0,          "65500"
HKR, Ndi\params\MTU,                step,       0,          "1"

HKR, Ndi\params\TxCapacity,         ParamDesc,  0,          %TxCapacity%
HKR, Ndi\params\TxCapacity,         type,       0,          "enum"
HKR, Ndi\params\TxCapacity,         default,    0,          "1024"
HKR, Ndi\Params\TxCapacity\enum,    "16",       0,          %String_16%
HKR, Ndi\Params\TxCapacity\enum,    "32",       0,          %String_32%
HKR, Ndi\Params\TxCapacity\enum,    "64",       0,          %String_64%
HKR, Ndi\Params\TxCapacity\enum,    "128",      0,          %String_128%
HKR, Ndi\Params\TxCapacity\enum,    "256",      0,          %String_256%
HKR, Ndi\Params\TxCapacity\enum,    "512",      0,          %String_512%
HKR, Ndi\Params\TxCapacity\enum,    "1024",     0,          %String_1024%
#if defined(_LargeQueueEntry)
HKR, Ndi\Params\TxCapacity\enum,    "2048",     0,          %String_2048%
HKR, Ndi\Params\TxCapacity\enum,    "4096",     0,          %String_4096%
HKR, Ndi\Params\TxCapacity\enum,    "8192",     0,          %String_8192%
#endif

HKR, Ndi\params\RxCapacity,         ParamDesc,  0,          %RxCapacity%
HKR, Ndi\params\RxCapacity,         type,       0,          "enum"
#if defined(_LargeQueueEntry)
HKR, Ndi\params\RxCapacity,         default,    0,          "8192"
#else
HKR, Ndi\params\RxCapacity,         default,    0,          "1024"
#endif
HKR, Ndi\Params\RxCapacity\enum,    "16",       0,          %String_16%
HKR, Ndi\Params\RxCapacity\enum,    "32",       0,          %String_32%
HKR, Ndi\Params\RxCapacity\enum,    "64",       0,          %String_64%
HKR, Ndi\Params\RxCapacity\enum,    "128",      0,          %String_128%
HKR, Ndi\Params\RxCapacity\enum,    "256",      0,          %String_256%
HKR, Ndi\Params\RxCapacity\enum,    "512",      0,          %String_512%
HKR, Ndi\Params\RxCapacity\enum,    "1024",     0,          %String_1024%
#if defined(_LargeQueueEntry)
HKR, Ndi\Params\RxCapacity\enum,    "2048",     0,          %String_2048%
HKR, Ndi\Params\RxCapacity\enum,    "4096",     0,          %String_4096%
HKR, Ndi\Params\RxCapacity\enum,    "8192",     0,          %String_8192%
#endif
HKR, Ndi\params\NetworkAddress,     ParamDesc,  0,          %NetworkAddress%
HKR, Ndi\params\NetworkAddress,     type,       0,          "edit"
HKR, Ndi\params\NetworkAddress,     Optional,   0,          "1"

HKR, Ndi\Params\OffLoad.TxChecksum, ParamDesc,  0,          %OffLoad.TxChecksum%
HKR, Ndi\Params\OffLoad.TxChecksum, Default,    0,          DEFAULT_TX_CHECKSUM
HKR, Ndi\Params\OffLoad.TxChecksum, type,       0,          "enum"
HKR, Ndi\Params\OffLoad.TxChecksum\enum,    "31",       0,  %All%
HKR, Ndi\Params\OffLoad.TxChecksum\enum,    "27",       0,  %TCPUDPAll%
HKR, Ndi\Params\OffLoad.TxChecksum\enum,    "3",        0,  %TCPUDPv4%
HKR, Ndi\Params\OffLoad.TxChecksum\enum,    "1",        0,  %TCPv4%
HKR, Ndi\Params\OffLoad.TxChecksum\enum,    "0",        0,  %Disable%

HKR, Ndi\Params\OffLoad.TxLSO,      ParamDesc,  0,          %OffLoad.TxLSO%
HKR, Ndi\Params\OffLoad.TxLSO,      Default,    0,          "2"
HKR, Ndi\Params\OffLoad.TxLSO,      type,       0,          "enum"
HKR, Ndi\Params\OffLoad.TxLSO\enum, "2",        0,          %Maximal%
HKR, Ndi\Params\OffLoad.TxLSO\enum, "1",        0,          %IPv4%
HKR, Ndi\Params\OffLoad.TxLSO\enum, "0",        0,          %Disable%

HKR, Ndi\Params\OffLoad.RxCS,       ParamDesc,  0,          %OffLoad.RxCS%
HKR, Ndi\Params\OffLoad.RxCS,       Default,    0,          DEFAULT_RX_CHECKSUM
HKR, Ndi\Params\OffLoad.RxCS,       type,       0,          "enum"
HKR, Ndi\Params\OffLoad.RxCS\enum,  "31",       0,          %All%
HKR, Ndi\Params\OffLoad.RxCS\enum,  "27",       0,          %TCPUDPAll%
HKR, Ndi\Params\OffLoad.RxCS\enum,  "3",        0,          %TCPUDPv4%
HKR, Ndi\Params\OffLoad.RxCS\enum,  "1",        0,          %TCPv4%
HKR, Ndi\Params\OffLoad.RxCS\enum,  "0",        0,          %Disable%

#if defined(_IPChecksumOffload)
HKR, Ndi\Params\*IPChecksumOffloadIPv4,     ParamDesc,  0,      %Std.IPChecksumOffloadv4%
HKR, Ndi\Params\*IPChecksumOffloadIPv4,     Default,    0,      "3"
HKR, Ndi\Params\*IPChecksumOffloadIPv4,     type,       0,      "enum"
HKR, Ndi\Params\*IPChecksumOffloadIPv4\enum,    "3",    0,      %TxRx%
HKR, Ndi\Params\*IPChecksumOffloadIPv4\enum,    "2",    0,      %Rx%
HKR, Ndi\Params\*IPChecksumOffloadIPv4\enum,    "1",    0,      %Tx%
HKR, Ndi\Params\*IPChecksumOffloadIPv4\enum,    "0",    0,      %Disable%
#endif

#if defined(_LsoV2IPv4)
HKR, Ndi\Params\*LsoV2IPv4,                 ParamDesc,  0,      %Std.LsoV2IPv4%
HKR, Ndi\Params\*LsoV2IPv4,                 Default,    0,      "1"
HKR, Ndi\Params\*LsoV2IPv4,                 type,       0,      "enum"
HKR, Ndi\Params\*LsoV2IPv4\enum,            "1",        0,      %Enable%
HKR, Ndi\Params\*LsoV2IPv4\enum,            "0",        0,      %Disable%
#endif

#if defined(_LsoV2IPv6)
HKR, Ndi\Params\*LsoV2IPv6,                 ParamDesc,  0,      %Std.LsoV2IPv6%
HKR, Ndi\Params\*LsoV2IPv6,                 Default,    0,      "1"
HKR, Ndi\Params\*LsoV2IPv6,                 type,       0,      "enum"
HKR, Ndi\Params\*LsoV2IPv6\enum,            "1",        0,      %Enable%
HKR, Ndi\Params\*LsoV2IPv6\enum,            "0",        0,      %Disable%
#endif

#if defined(_UDPChecksumOffloadIPv4)
HKR, Ndi\Params\*UDPChecksumOffloadIPv4,    ParamDesc,  0,      %Std.UDPChecksumOffloadIPv4%
HKR, Ndi\Params\*UDPChecksumOffloadIPv4,    Default,    0,      "3"
HKR, Ndi\Params\*UDPChecksumOffloadIPv4,    type,       0,      "enum"
HKR, Ndi\Params\*UDPChecksumOffloadIPv4\enum,   "3",    0,      %TxRx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv4\enum,   "2",    0,      %Rx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv4\enum,   "1",    0,      %Tx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv4\enum,   "0",    0,      %Disable%
#endif

#if defined(_TCPChecksumOffloadIPv4)
HKR, Ndi\Params\*TCPChecksumOffloadIPv4,    ParamDesc,  0,      %Std.TCPChecksumOffloadIPv4%
HKR, Ndi\Params\*TCPChecksumOffloadIPv4,    Default,    0,      "3"
HKR, Ndi\Params\*TCPChecksumOffloadIPv4,    type,       0,      "enum"
HKR, Ndi\Params\*TCPChecksumOffloadIPv4\enum,   "3",    0,      %TxRx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv4\enum,   "2",    0,      %Rx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv4\enum,   "1",    0,      %Tx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv4\enum,   "0",    0,      %Disable%
#endif


#if defined(_TCPChecksumOffloadIPv6)
HKR, Ndi\Params\*TCPChecksumOffloadIPv6,    ParamDesc,  0,      %Std.TCPChecksumOffloadIPv6%
HKR, Ndi\Params\*TCPChecksumOffloadIPv6,    Default,    0,      "3"
HKR, Ndi\Params\*TCPChecksumOffloadIPv6,    type,       0,      "enum"
HKR, Ndi\Params\*TCPChecksumOffloadIPv6\enum,   "3",    0,      %TxRx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv6\enum,   "2",    0,      %Rx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv6\enum,   "1",    0,      %Tx%
HKR, Ndi\Params\*TCPChecksumOffloadIPv6\enum,   "0",    0,      %Disable%
#endif

#if defined(_UDPChecksumOffloadIPv6)
HKR, Ndi\Params\*UDPChecksumOffloadIPv6,    ParamDesc,  0,      %Std.UDPChecksumOffloadIPv6%
HKR, Ndi\Params\*UDPChecksumOffloadIPv6,    Default,    0,      "3"
HKR, Ndi\Params\*UDPChecksumOffloadIPv6,    type,       0,      "enum"
HKR, Ndi\Params\*UDPChecksumOffloadIPv6\enum,   "3",    0,      %TxRx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv6\enum,   "2",    0,      %Rx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv6\enum,   "1",    0,      %Tx%
HKR, Ndi\Params\*UDPChecksumOffloadIPv6\enum,   "0",    0,      %Disable%
#endif

#if defined(INCLUDE_TEST_PARAMS)
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       ParamDesc,  0,          %NumberOfHandledRXPackersInDPC%
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       type,       0,          "long"
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       default,    0,          "1000"
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       min,        0,          "1"
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       max,        0,          "10000"
HKR, Ndi\params\NumberOfHandledRXPackersInDPC,       step,       0,          "1"
#endif

#endif

#if defined(INCLUDE_STRINGS)
NetworkAddress = "Assign MAC"
ConnectRate = "Init.ConnectionRate(Mb)"
Priority = "Init.Do802.1PQ"
MTU = "Init.MTUSize"
TxCapacity = "Init.MaxTxBuffers"
RxCapacity = "Init.MaxRxBuffers"
Offload.TxChecksum = "Offload.Tx.Checksum"
Offload.TxLSO = "Offload.Tx.LSO"
Offload.RxCS = "Offload.Rx.Checksum"
EnableLogging = "Logging.Enable"
DebugLevel = "Logging.Level"
Tx = "Tx Enabled";
Rx = "Rx Enabled";
TxRx = "Rx & Tx Enabled";
Rss = "Receive Side Scaling"
MaxRssQueues = "Maximum Number of RSS Queues"
RscIPv4= "RscIPv4"
RscIPv6= "RscIPv6"

#if defined(INCLUDE_TEST_PARAMS)
NumberOfHandledRXPackersInDPC = "TestOnly.RXThrottle"
#endif

#if defined(_LsoV2IPv4)
Std.LsoV2IPv4 = "Large Send Offload V2 (IPv4)"
#endif

#if defined(_LsoV2IPv6)
Std.LsoV2IPv6 = "Large Send Offload V2 (IPv6)"
#endif

#if defined(_UDPChecksumOffloadIPv4)
Std.UDPChecksumOffloadIPv4 = "UDP Checksum Offload (IPv4)"
#endif

#if defined(_TCPChecksumOffloadIPv4)
Std.TCPChecksumOffloadIPv4 = "TCP Checksum Offload (IPv4)"
#endif

#if defined(_UDPChecksumOffloadIPv6)
Std.UDPChecksumOffloadIPv6 = "UDP Checksum Offload (IPv6)"
#endif

#if defined(_TCPChecksumOffloadIPv6)
Std.TCPChecksumOffloadIPv6 = "TCP Checksum Offload (IPv6)"
#endif

#if defined(_IPChecksumOffload)
Std.IPChecksumOffloadv4 = "IPv4 Checksum Offload"
#endif

Disable = "Disabled"
Enable  = "Enabled"
Enable* = "Enabled*"
String_16 = "16"
String_32 = "32"
String_64 = "64"
String_128 = "128"
String_256 = "256"
String_512 = "512"
String_1024 = "1024"
#if defined(_LargeQueueEntry)
String_2048 = "2048"
String_4096 = "4096"
String_8192 = "8192"
#endif

PriorityVlanTag = "Priority and VLAN tagging"
PriorityOnly = "Priority"
VLan = "VLan"
Priority_Vlan = "All"
10M = "10M"
100M = "100M"
1G   = "1G"
10G = "10G"
TCPv4 = "TCP(v4)"
TCPUDPv4 = "TCP/UDP(v4)"
TCPUDPAll = "TCP/UDP(v4,v6)"
All = "All"
IPv4 = "IPv4"
Maximal = "Maximal"
#endif
