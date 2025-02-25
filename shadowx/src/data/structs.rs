use wdk_sys::*;
use bitfield::bitfield;
use common::enums::Callbacks;
use super::COMUNICATION_TYPE;
use core::{ffi::c_void, mem::ManuallyDrop};

bitfield! {
    pub struct PS_PROTECTION(u8);
    pub u8, Type, SetType: 2, 0;
    pub u8, Audit, SetAudit: 3;
    pub u8, Signer, SetSigner: 7, 4;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KBUGCHECK_REASON_CALLBACK_RECORD {
    pub Entry: LIST_ENTRY,
    pub CallbackRoutine: PKBUGCHECK_REASON_CALLBACK_ROUTINE,
    pub Component: PUCHAR,
    pub Checksum: usize,
    pub Reason: KBUGCHECK_CALLBACK_REASON,
    pub State: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*mut c_void; 3],
    pub AtlThunkSListPtr: *mut c_void,
    pub Reserved5: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LDR_DATA_TABLE_ENTRY {
	pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
	pub InInitializationOrderLinks: LIST_ENTRY,
	pub DllBase: *mut c_void,
	pub EntryPoint: *mut c_void,
	pub SizeOfImage: u32,
	pub FullDllName: UNICODE_STRING,
	pub BaseDllName: UNICODE_STRING,
	pub Flags: u32,
	pub LoadCount: u32,
	pub TlsIndex: u16,
	pub HashLinks: LIST_ENTRY,
	pub TimeDateStamp: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

#[repr(C)]
pub struct PROCESS_SIGNATURE {
    pub SignatureLevel: u8,
    pub SectionSignatureLevel: u8,
    pub Protection: PS_PROTECTION,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModuleInformation {
    pub ModuleCount: u32,
    pub Modules: [SystemModule; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemModule {
    pub Section: *mut c_void,
    pub MappedBase: *mut c_void,
    pub ImageBase: *mut c_void,
    pub Size: u32,
    pub Flags: u32,
    pub Index: u8,
    pub NameLength: u8,
    pub LoadCount: u8,
    pub PathLength: u8,
    pub ImageName: [u8; 256],
}

#[repr(C)]
pub struct MMVAD_SHORT {
    pub VadNode: RTL_BALANCED_NODE,
    pub StartingVpn: u32,
    pub EndingVpn: u32,
    pub StartingVpnHigh: u8,
    pub EndingVpnHigh: u8,
    pub CommitChargeHigh: u8,
    pub SpareNT64VadUChar: u8,
    pub ReferenceCount: i32,
    pub PushLock: usize,
    pub u: MMVAD_SHORT_0,
    pub u1: MMVAD_SHORT_0_0,
    pub u5: MMVAD_SHORT_0_0_0,
}

#[repr(C)]
pub union MMVAD_SHORT_0 {
    pub LongFlags: u32,
    pub VadFlags: ManuallyDrop<MMVAD_FLAGS>,
    pub PrivateVadFlags: ManuallyDrop<MM_PRIVATE_VAD_FLAGS>,
    pub GraphicsVadFlags: ManuallyDrop<MM_GRAPHICS_VAD_FLAGS>,
    pub SharedVadFlags: ManuallyDrop<MM_SHARED_VAD_FLAGS>,
    pub VolatileLong: u32,
}

#[repr(C)]
pub union MMVAD_SHORT_0_0 {
    pub LongFlags1: u32,
    pub VadFlags1: ManuallyDrop<MMVAD_FLAGS1>,
}

#[repr(C)]
pub union MMVAD_SHORT_0_0_0 {
    pub EventListUlongPtr: u64,
    pub StartingVpnHigher: u8,
}

#[repr(C)]
pub struct SUBSECTION {
    pub ControlArea: *mut CONTROL_AREA,
}

#[repr(C)]
pub struct CONTROL_AREA {
    Segment: *mut *mut c_void,
    ListOrAweContext: LIST_OR_AWE_CONTEXT,
    NumberOfSectionReferences: u64,
    NumberOfPfnReferences: u64,
    NumberOfMappedViews: u64,
    NumberOfUserReferences: u64,
    u: CONTROL_AREA_0,
    u1: CONTROL_AREA_0_0,
    pub FilePointer: EX_FAST_REF,
}

#[repr(C)]
pub struct EX_FAST_REF {
    pub Inner: EX_FAST_REF_INNER,
}

#[repr(C)]
pub union EX_FAST_REF_INNER {
    pub Object: *mut c_void,
    pub Value: u64,
}

#[repr(C)]
pub union CONTROL_AREA_0 {
    LongFlags: u32,
    Flags: u32,
}

#[repr(C)]
pub union CONTROL_AREA_0_0 {
    LongFlags: u32,
    Flags: u32,
}

#[repr(C)]
pub union LIST_OR_AWE_CONTEXT {
    ListHead: LIST_ENTRY,
    AweContext: *mut c_void,
}

#[repr(C)]
pub struct MMVAD {
    Core: MMVAD_SHORT,
    u2: MMVAD_0,
    pub SubSection: *mut SUBSECTION,
}

#[repr(C)]
pub union MMVAD_0 {
    LongFlags2: u32,
    VadFlags2: ManuallyDrop<MMVAD_FLAGS2>,
}

bitfield! {
    #[repr(C)]
    pub struct MMVAD_FLAGS(u32);
    impl Debug;
    u32;
    pub Lock, SetLock: 0;
    pub LockContended, SetLockContended: 1;
    pub DeleteInProgress, SetDeleteInProgress: 2;
    pub NoChange, SetNoChange: 3;
    pub VadType, SetVadType: 6, 4;
    pub Protection, SetProtection: 11, 7;
    pub PreferredNode, SetPreferredNode: 18, 12;
    pub PageSize, SetPageSize: 19, 20;
    pub PrivateMemory, SetPrivateMemory: 21;
}

bitfield! {
    #[repr(C)]
    pub struct MMVAD_FLAGS1(u32);
    impl Debug;
    pub CommitCharge, SetCommitCharge: 30, 0;
    pub MemCommit, SetMemCommit: 31;
}

bitfield! {
    #[repr(C)]
    pub struct MMVAD_FLAGS2(u32);
    impl Debug;
    u32;
    pub FileOffset, SetFileOffset: 0, 23;
    pub Large, SetLarge: 24;
    pub TrimBehind, SetTrimBehind: 25;
    pub Inherit, SetInherit: 26;
    pub NoValidationNeeded, SetNoValidationNeeded: 27;
    pub PrivateDemandZEro, SetPrivateDemandZero: 28;
    pub Spare, SetSpare: 29, 31;
}

bitfield! {
    #[repr(C)]
    pub struct MM_SHARED_VAD_FLAGS(u32);
    impl Debug;
    u32;
    pub Lock, SetLock: 1;
    pub LockContended, SetLockContended: 1;
    pub DeleteInProgress, SetDeleteInProgress: 1;
    pub NoChange, SetNoChange: 1;
    pub VadType, SetVadType: 6, 4;
    pub Protection, SetProtection: 11, 7;
    pub PreferredNode, SetPreferredNode: 18, 12;
    pub PageSize, SetPageSize: 19, 20;
    pub PrivateMemoryAlwaysSet, SetPrivateMemory: 21;
    pub PrivateFixup, SetPrivateFixup: 22;
    pub HotPatchState, SetHotPatchState: 24, 23;
}

bitfield! {
    #[repr(C)]
    pub struct MM_PRIVATE_VAD_FLAGS(u32);
    impl Debug;
    u32;
    pub Lock, SetLock: 1;
    pub LockContended, SetLockContended: 1;
    pub DeleteInProgress, SetDeleteInProgress: 1;
    pub NoChange, SetNoChange: 1;
    pub VadType, SetVadType: 6, 4;
    pub Protection, SetProtection: 11, 7;
    pub PreferredNode, SetPreferredNode: 18, 12;
    pub PageSize, SetPageSize: 19, 20;
    pub PrivateMemoryAlwaysSet, SetPrivateMemory: 21;
    pub Writewatch, setWrite: 22;
    pub FixedLargePageSize, SetPageLarge: 23;
    pub ZeroFillPagesOptional, SetZeroFill: 24;
    pub Graphics, SetGraphics: 25;
    pub Enclave, SetEnclave: 26;
    pub ShadowStack, SetShadowStack: 27;
    pub PhysicalMemoryPfnsReferenced, SetPhysical: 28;
}

bitfield! {
    #[repr(C)]
    pub struct MM_GRAPHICS_VAD_FLAGS(u32);
    impl Debug;
    u32;
    pub Lock, SetLock: 1;
    pub LockContended, SetLockContended: 1;
    pub DeleteInProgress, SetDeleteInProgress: 1;
    pub NoChange, SetNoChange: 1;
    pub VadType, SetVadType: 6, 4;
    pub Protection, SetProtection: 11, 7;
    pub PreferredNode, SetPreferredNode: 18, 12;
    pub PageSize, SetPageSize: 19, 20;
    pub PrivateMemoryAlwaysSet, SetPrivateMemory: 21;
    pub Writewatch, setWrite: 22;
    pub FixedLargePageSize, SetPageLarge: 23;
    pub ZeroFillPagesOptional, SetZeroFill: 24;
    pub GraphicsAlwaysSet, SetGraphicsAlwaysSet: 25;
    pub GraphicsUseCoherent, SetGraphicsUseCoherent: 26;
    pub GraphicsNoCache, SetGraphicsNoCache: 27;
    pub GraphicsPageProtection, SetGraphicsPageProtection: 30, 28;
}

#[repr(C)]
pub struct TRACE_ENABLE_INFO {
    pub IsEnabled: u32,
    pub Level: u8,
    pub Reserved1: u8,
    pub LoggerId: u16,
    pub EnableProperty: u32,
    pub Reserved2: u32,
    pub MatchAnyKeyword: u64,
    pub MatchAllKeyword: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct NSI_TCP_ENTRY {
    pub Reserved1: [u8; 2],
    pub Port: u16,
    pub IpAddress: u32,
    pub IpAddress6: [u8; 16],
    pub Reserved2: [u8; 4],
}

#[repr(C)]
#[derive(Debug)]
pub struct NSI_TABLE_TCP_ENTRY {
    pub Local: NSI_TCP_ENTRY,
    pub Remote: NSI_TCP_ENTRY,
}

#[repr(C)]
pub struct NSI_UDP_ENTRY {
    pub Reserved1: [u8; 2],
    pub Port: u16,
    pub IpAddress: u32,
    pub IpAddress6: [u8; 16],
    pub Reserved2: [u8; 4],
}

#[repr(C)]
pub struct NSI_PARAM {
    pub Reserved1: usize,
    pub Reverved2: usize,
    pub ModuleId: *mut core::ffi::c_void,
    pub Type_: COMUNICATION_TYPE,
    pub Reserved3: u32,
    pub Reserved4: u32,
    pub Entries: *mut core::ffi::c_void,
    pub EntrySize: usize,
    pub Reserved5: *mut core::ffi::c_void,
    pub Reserved6: usize,
    pub StatusEntries: *mut NSI_STATUS_ENTRY,
    pub Reserved7: usize,
    pub ProcessEntries: *mut NSI_PROCESS_ENTRY,
    pub ProcessEntrySize: usize,
    pub Count: usize,
}

#[repr(C)]
pub struct NSI_STATUS_ENTRY {
    pub State: u32,
    pub Reserved: [u8; 8],
}

#[repr(C)]
pub struct NSI_PROCESS_ENTRY {
    pub UdpProcessId: u32,
    pub Reserved1: u32,
    pub Reserved2: u32,
    pub TcpProcessId: u32,
    pub Reserved3: u32,
    pub Reserved4: u32,
    pub Reserved5: u32,
    pub Reserved6: u32,
}

#[repr(C)]
pub struct FULL_OBJECT_TYPE {
    pub TypeList: LIST_ENTRY,
    pub Name: UNICODE_STRING,
    pub DefaultObject: *mut c_void,
    pub Index: u8,
    pub TotalNumberOf_Objects: u32,
    pub TotalNumberOfHandles: u32,
    pub HighWaterNumberOfObjects: u32,
    pub HighWaterNumberOfHandles: u32,
    pub TypeInfo: [u8; 0x78],
    pub TypeLock: _EX_PUSH_LOCK,
    pub Key: u32,
    pub CallbackList: LIST_ENTRY,
}

bitfield! {
    pub struct _EX_PUSH_LOCK(u64);
    impl Debug;
    u64;
    Locked, SetLocked: 0;
    Waiting, SetWaiting: 1;
    Waking, Setwaking: 2;
    MultipleShared, SetMultipleShared: 3;
    Shared, SetShared: 63, 4;
}

#[repr(C)]
#[derive(Default)]
pub struct CallbackRestaure {
    pub index: usize,
    pub callback: Callbacks,
    pub address: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct CallbackRestaureOb {
    pub index: usize,
    pub callback: Callbacks,
    pub pre_operation: u64,
    pub post_operation: u64,
    pub entry: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CM_CALLBACK {
    pub List: LIST_ENTRY,
    pub Unknown1: [u64; 2],
    pub Context: u64,
    pub Function: u64,
    pub Altitude: UNICODE_STRING,
    pub Unknown2: [u64; 2],
}

#[repr(C)]
pub struct OBCALLBACK_ENTRY {
    pub CallbackList: LIST_ENTRY,
    pub Operations: OB_OPERATION,
    pub Enabled: bool,
    pub Entry: *mut OB_CALLBACK,
    pub ObjectType: POBJECT_TYPE,
    pub PreOperation: POB_PRE_OPERATION_CALLBACK,
    pub PostOperation: POB_POST_OPERATION_CALLBACK,
    pub Lock: KSPIN_LOCK,
}

#[repr(C)]
pub struct OB_CALLBACK {
    pub Version: u16,
    pub OperationRegistrationCount: u16,
    pub RegistrationContext: *mut c_void,
    pub AltitudeString: UNICODE_STRING,
    pub EntryItems: [OBCALLBACK_ENTRY; 1],
    pub AltitudeBuffer: [u16; 1],
}
