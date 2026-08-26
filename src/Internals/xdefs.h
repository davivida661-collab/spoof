#pragma once
#include <ntifs.h>


#ifdef DBG
#define LOG(format, ...) DbgPrintEx(0, 0, format, ##__VA_ARGS__)

#else
#define LOG(format, ...) ((void)0)

#endif

using BYTE = unsigned char;


extern "C" {
NTSTATUS NTAPI ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle,
                                      _Inout_ PVOID* BaseAddress,
                                      _Inout_ PSIZE_T RegionSize,
                                      _In_ ULONG NewProtection,
                                      _Out_ PULONG OldProtection);

NTSTATUS
ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
                         ULONG SystemInformationLength, PULONG ReturnLength);

NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG OpenOptions
);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);
}



EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(ULONG infoClass, void* buf, ULONG length);


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;
	USHORT PathLength;
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE_ENTRY;


typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	ULONG Unknown1;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
  *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;



//TRACE

enum EtwpTrace
{
	EtwpStartTrace      = 1,
	EtwpStopTrace       = 2,
	EtwpQueryTrace      = 3,
	EtwpUpdateTrace     = 4,
	EtwpFlushTrace      = 5
};


constexpr auto  _syscallId = 0xf33ul;

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

#pragma warning(push)
#pragma warning(disable : 4201)

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union
	{
		ULONG64 HistoricalContext;
		struct
		{
			ULONG Version;
			ULONG Linkage;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	} DUMMYUNIONNAME2;
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER;

#pragma warning(pop)

typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES;

const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

typedef struct _CKCL_TRACE_PROPERTIES : EVENT_TRACE_PROPERTIES
{
	ULONG64						Unknown[3];
	UNICODE_STRING				ProviderName;
} CKCL_TRACE_PROPERTIES;

typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
	EventTraceKernelVersionInformation,
	EventTraceGroupMaskInformation,
	EventTracePerformanceInformation,
	EventTraceTimeProfileInformation,
	EventTraceSessionSecurityInformation,
	EventTraceSpinlockInformation,
	EventTraceStackTracingInformation,
	EventTraceExecutiveResourceInformation,
	EventTraceHeapTracingInformation,
	EventTraceHeapSummaryTracingInformation,
	EventTracePoolTagFilterInformation,
	EventTracePebsTracingInformation,
	EventTraceProfileConfigInformation,
	EventTraceProfileSourceListInformation,
	EventTraceProfileEventListInformation,
	EventTraceProfileCounterListInformation,
	EventTraceStackCachingInformation,
	EventTraceObjectTypeFilterInformation,
	MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, * PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, * PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

const ULONG SystemPerformanceTraceInformation = 31;



typedef struct _DBGKD_DEBUG_DATA_HEADER64
		{
			LIST_ENTRY64 List;
			ULONG           OwnerTag;
			ULONG           Size;
		} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64
		{

			DBGKD_DEBUG_DATA_HEADER64 Header;

			ULONG64   KernBase;

			ULONG64   BreakpointWithStatus;

			ULONG64   SavedContext;

			USHORT  ThCallbackStack;
			USHORT  NextCallback;
			USHORT  FramePointer;
			USHORT  PaeEnabled;

			ULONG64   KiCallUserMode;
			ULONG64   KeUserCallbackDispatcher;

			ULONG64   PsLoadedModuleList;
			ULONG64   PsActiveProcessHead;
			ULONG64   PspCidTable;

			ULONG64   ExpSystemResourcesList;
			ULONG64   ExpPagedPoolDescriptor;
			ULONG64   ExpNumberOfPagedPools;

			ULONG64   KeTimeIncrement;
			ULONG64   KeBugCheckCallbackListHead;
			ULONG64   KiBugcheckData;

			ULONG64   IopErrorLogListHead;

			ULONG64   ObpRootDirectoryObject;
			ULONG64   ObpTypeObjectType;

			ULONG64   MmSystemCacheStart;
			ULONG64   MmSystemCacheEnd;
			ULONG64   MmSystemCacheWs;

			ULONG64   MmPfnDatabase;
			ULONG64   MmSystemPtesStart;
			ULONG64   MmSystemPtesEnd;
			ULONG64   MmSubsectionBase;
			ULONG64   MmNumberOfPagingFiles;

			ULONG64   MmLowestPhysicalPage;
			ULONG64   MmHighestPhysicalPage;
			ULONG64   MmNumberOfPhysicalPages;

			ULONG64   MmMaximumNonPagedPoolInBytes;
			ULONG64   MmNonPagedSystemStart;
			ULONG64   MmNonPagedPoolStart;
			ULONG64   MmNonPagedPoolEnd;

			ULONG64   MmPagedPoolStart;
			ULONG64   MmPagedPoolEnd;
			ULONG64   MmPagedPoolInformation;
			ULONG64   MmPageSize;

			ULONG64   MmSizeOfPagedPoolInBytes;

			ULONG64   MmTotalCommitLimit;
			ULONG64   MmTotalCommittedPages;
			ULONG64   MmSharedCommit;
			ULONG64   MmDriverCommit;
			ULONG64   MmProcessCommit;
			ULONG64   MmPagedPoolCommit;
			ULONG64   MmExtendedCommit;

			ULONG64   MmZeroedPageListHead;
			ULONG64   MmFreePageListHead;
			ULONG64   MmStandbyPageListHead;
			ULONG64   MmModifiedPageListHead;
			ULONG64   MmModifiedNoWritePageListHead;
			ULONG64   MmAvailablePages;
			ULONG64   MmResidentAvailablePages;

			ULONG64   PoolTrackTable;
			ULONG64   NonPagedPoolDescriptor;

			ULONG64   MmHighestUserAddress;
			ULONG64   MmSystemRangeStart;
			ULONG64   MmUserProbeAddress;

			ULONG64   KdPrintCircularBuffer;
			ULONG64   KdPrintCircularBufferEnd;
			ULONG64   KdPrintWritePointer;
			ULONG64   KdPrintRolloverCount;

			ULONG64   MmLoadedUserImageList;

			// NT 5.1 Addition

			ULONG64   NtBuildLab;
			ULONG64   KiNormalSystemCall;

			// NT 5.0 hotfix addition

			ULONG64   KiProcessorBlock;
			ULONG64   MmUnloadedDrivers;
			ULONG64   MmLastUnloadedDriver;
			ULONG64   MmTriageActionTaken;
			ULONG64   MmSpecialPoolTag;
			ULONG64   KernelVerifier;
			ULONG64   MmVerifierData;
			ULONG64   MmAllocatedNonPagedPool;
			ULONG64   MmPeakCommitment;
			ULONG64   MmTotalCommitLimitMaximum;
			ULONG64   CmNtCSDVersion;

			// NT 5.1 Addition

			ULONG64   MmPhysicalMemoryBlock;
			ULONG64   MmSessionBase;
			ULONG64   MmSessionSize;
			ULONG64   MmSystemParentTablePage;

			// Server 2003 addition

			ULONG64   MmVirtualTranslationBase;

			USHORT    OffsetKThreadNextProcessor;
			USHORT    OffsetKThreadTeb;
			USHORT    OffsetKThreadKernelStack;
			USHORT    OffsetKThreadInitialStack;

			USHORT    OffsetKThreadApcProcess;
			USHORT    OffsetKThreadState;
			USHORT    OffsetKThreadBStore;
			USHORT    OffsetKThreadBStoreLimit;

			USHORT    SizeEProcess;
			USHORT    OffsetEprocessPeb;
			USHORT    OffsetEprocessParentCID;
			USHORT    OffsetEprocessDirectoryTableBase;

			USHORT    SizePrcb;
			USHORT    OffsetPrcbDpcRoutine;
			USHORT    OffsetPrcbCurrentThread;
			USHORT    OffsetPrcbMhz;

			USHORT    OffsetPrcbCpuType;
			USHORT    OffsetPrcbVendorString;
			USHORT    OffsetPrcbProcStateContext;
			USHORT    OffsetPrcbNumber;

			USHORT    SizeEThread;

			ULONG64   KdPrintCircularBufferPtr;
			ULONG64   KdPrintBufferSize;

			ULONG64   KeLoaderBlock;

			USHORT    SizePcr;
			USHORT    OffsetPcrSelfPcr;
			USHORT    OffsetPcrCurrentPrcb;
			USHORT    OffsetPcrContainedPrcb;

			USHORT    OffsetPcrInitialBStore;
			USHORT    OffsetPcrBStoreLimit;
			USHORT    OffsetPcrInitialStack;
			USHORT    OffsetPcrStackLimit;

			USHORT    OffsetPrcbPcrPage;
			USHORT    OffsetPrcbProcStateSpecialReg;
			USHORT    GdtR0Code;
			USHORT    GdtR0Data;

			USHORT    GdtR0Pcr;
			USHORT    GdtR3Code;
			USHORT    GdtR3Data;
			USHORT    GdtR3Teb;

			USHORT    GdtLdt;
			USHORT    GdtTss;
			USHORT    Gdt64R3CmCode;
			USHORT    Gdt64R3CmTeb;

			ULONG64   IopNumTriageDumpDataBlocks;
			ULONG64   IopTriageDumpDataBlocks;

			// Longhorn addition

			ULONG64   VfCrashDataBlock;
			ULONG64   MmBadPagesDetected;
			ULONG64   MmZeroedPageSingleBitErrorsDetected;

			// Windows 7 addition

			ULONG64   EtwpDebuggerData;
			USHORT    OffsetPrcbContext;

			// Windows 8 addition

			USHORT    OffsetPrcbMaxBreakpoints;
			USHORT    OffsetPrcbMaxWatchpoints;

			ULONG     OffsetKThreadStackLimit;
			ULONG     OffsetKThreadStackBase;
			ULONG     OffsetKThreadQueueListEntry;
			ULONG     OffsetEThreadIrpList;

			USHORT    OffsetPrcbIdleThread;
			USHORT    OffsetPrcbNormalDpcState;
			USHORT    OffsetPrcbDpcStack;
			USHORT    OffsetPrcbIsrStack;

			USHORT    SizeKDPC_STACK_FRAME;

			// Windows 8.1 Addition

			USHORT    OffsetKPriQueueThreadListHead;
			USHORT    OffsetKThreadWaitReason;

			// Windows 10 RS1 Addition

			USHORT    Padding;
			ULONG64   PteBase;

			// Windows 10 RS5 Addition

			ULONG64 RetpolineStubFunctionTable;
			ULONG RetpolineStubFunctionTableSize;
			ULONG RetpolineStubOffset;
			ULONG RetpolineStubSize;

		} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;
