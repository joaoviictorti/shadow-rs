use super::*; 
use wdk_sys::*;
    
pub type DRIVER_INITIALIZE = core::option::Option<unsafe extern "system" fn(
    DriverObject: &mut _DRIVER_OBJECT,
    RegistryPath: PCUNICODE_STRING,
) -> NTSTATUS>;

pub type ZwCreateThreadExType = unsafe extern "system" fn (
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
    AttributeList: PPS_ATTRIBUTE_LIST
) -> NTSTATUS;

pub type PKRUNDOWN_ROUTINE = Option<unsafe extern "system" fn(
    apc: PKAPC,
) -> NTSTATUS>;

pub type PKNORMAL_ROUTINE =  Option<unsafe extern "system" fn(
    normal_context: *mut PVOID,
    system_argument1: *mut PVOID,
    system_argument2: *mut PVOID
) -> NTSTATUS>;

pub type PKKERNEL_ROUTINE = unsafe extern "system" fn(
    apc: PKAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    normal_context: *mut PVOID,
    system_argument1: *mut PVOID,
    system_argument2: *mut PVOID 
);