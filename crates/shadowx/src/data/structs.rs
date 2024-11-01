use {
    wdk_sys::*,
    bitfield::bitfield, 
    common::enums::Callbacks, 
    core::{ffi::c_void, mem::ManuallyDrop},
};


use super::COMUNICATION_TYPE;

bitfield! {
    pub struct PS_PROTECTION(u8);
    pub u8, Type, SetType: 2, 0;   
    pub u8, Audit, SetAudit: 3;      
    pub u8, Signer, SetSigner: 7, 4;
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
    pub FilePointer: EX_FAST_REF
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
    pub SubSection: *mut SUBSECTION
}

#[repr(C)]
pub union MMVAD_0 {
    LongFlags2: u32,
    VadFlags2: ManuallyDrop<MMVAD_FLAGS2>
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
    pub MatchAllKeyword: u64
}


#[repr(C)]
#[derive(Debug)]
pub struct NSI_TCP_ENTRY {
    pub Reserved1: [u8; 2],
    pub Port: u16,
    pub IpAddress: u32,
    pub IpAddress6: [u8; 16],
    pub Reserved2: [u8; 4]
}

#[repr(C)]
#[derive(Debug)]
pub struct NSI_TABLE_TCP_ENTRY {
    pub Local: NSI_TCP_ENTRY,
    pub Remote: NSI_TCP_ENTRY
}

#[repr(C)]
pub struct NSI_UDP_ENTRY {
    pub Reserved1: [u8; 2],
    pub Port: u16,
    pub IpAddress: u32,
    pub IpAddress6: [u8; 16],
    pub Reserved2: [u8; 4]
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
    pub Count: usize
}

#[repr(C)]
pub struct NSI_STATUS_ENTRY {
    pub State: u32,
    pub Reserved: [u8; 8]
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
    pub Reserved6: u32
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
pub struct CallbackRestaureOb{
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
    pub Lock: KSPIN_LOCK
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