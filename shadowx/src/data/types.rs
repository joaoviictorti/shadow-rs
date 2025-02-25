use wdk_sys::*;
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use crate::data::KBUGCHECK_REASON_CALLBACK_RECORD;

pub type PKRUNDOWN_ROUTINE = Option<unsafe extern "system" fn(APC: PKAPC) -> NTSTATUS>;
pub type DRIVER_INITIALIZE = Option<unsafe extern "system" fn(DriverObject: &mut _DRIVER_OBJECT, RegistryPath: PCUNICODE_STRING) -> NTSTATUS>;
pub type PKNORMAL_ROUTINE = Option<unsafe extern "system" fn(NormalContext: *mut PVOID, SystemArgument1: *mut PVOID, SystemArgument2: *mut PVOID) -> NTSTATUS>;
pub type PKKERNEL_ROUTINE = unsafe extern "system" fn(APC: PKAPC, NormalRoutine: *mut PKNORMAL_ROUTINE, NormalContext: *mut PVOID, SystemArgument1: *mut PVOID, SystemArgument2: *mut PVOID);
pub type KBUGCHECK_REASON_CALLBACK_ROUTINE = Option<unsafe extern "C" fn(Reason: KBUGCHECK_CALLBACK_REASON, Record: *mut KBUGCHECK_REASON_CALLBACK_RECORD, ReasonSpecificData: PVOID, ReasonSpecificDataLength: ULONG)>;
pub type ZwCreateThreadExType = unsafe extern "system" fn(
    ThreadHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: SIZE_T,
    ZeroBits: usize,
    StackSize: usize,
    MaximumStackSize: usize,
    AttributeList: PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;

