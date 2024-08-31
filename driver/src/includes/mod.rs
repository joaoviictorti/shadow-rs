#![allow(non_camel_case_types)]
#![allow(dead_code)]

use {
    bitfield::bitfield, 
    ntapi::ntpsapi::PPS_ATTRIBUTE_LIST, 
    shared::structs::LIST_ENTRY, 
    wdk_sys::*, 
    winapi::ctypes::c_void
};

pub mod structs {
    use super::*;
    use shared::vars::Callbacks;

    #[repr(C)]
    pub struct FULL_OBJECT_TYPE {
        type_list: LIST_ENTRY,
        name: UNICODE_STRING,
        default_object: *mut c_void,
        index: u8,
        total_number_of_objects: u32,
        pub total_number_of_handles: u32,
        high_water_number_of_objects: u32,
        high_water_number_of_handles: u32,
        type_info: [u8; 0x78],
        pub type_lock: _EX_PUSH_LOCK,
        key: u32,
        pub callback_list: LIST_ENTRY,
    }
    
    #[repr(C)]
    pub struct OBCALLBACK_ENTRY {
        pub callback_list: LIST_ENTRY,
        operations: OB_OPERATION,
        pub enabled: bool,
        pub entry: *mut OB_CALLBACK,
        object_type: POBJECT_TYPE,
        pub pre_operation: POB_PRE_OPERATION_CALLBACK,
        pub post_operation: POB_POST_OPERATION_CALLBACK,
        lock: KSPIN_LOCK
    }
    
    #[repr(C)]
    pub struct OB_CALLBACK {
        version: u16,
        operation_registration_count: u16,
        registration_context: *mut c_void,
        altitude_string: UNICODE_STRING,
        entry_items: [OBCALLBACK_ENTRY; 1],
        altitude_buffer: [u16; 1],
    }
    
    pub struct PROCESS_SIGNATURE {
        pub signature_level: u8,
        pub section_seginature_level: u8,
        pub protection: PS_PROTECTION,
    }
    
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SystemModule {
        pub section: *mut c_void,
        pub mapped_base: *mut c_void,
        pub image_base: *mut c_void,
        pub size: u32,
        pub flags: u32,
        pub index: u8,
        pub name_length: u8,
        pub load_count: u8,
        pub path_length: u8,
        pub image_name: [u8; 256],
    }
    
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct SystemModuleInformation {
        pub modules_count: u32,
        pub modules: [SystemModule; 256],
    }
    
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct CM_CALLBACK {
        pub list: LIST_ENTRY,
        unknown1: [u64; 2],
        context: u64,
        pub function: u64,
        altitude: UNICODE_STRING,
        unknown2: [u64; 2],
    }
    
    bitfield! {
        pub struct _EX_PUSH_LOCK(u64);
        impl Debug;
        u64;
        locked, set_locked: 0;
        waiting, set_waiting: 1;
        waking, set_waking: 2;
        multiple_shared, set_multiple_shared: 3;
        shared, set_shared: 63, 4;
    }

    #[repr(C)]
    union ExPushLockUnion {
        struct_data: core::mem::ManuallyDrop<_EX_PUSH_LOCK>,
        value: u64,
        ptr: *mut c_void,
    }
    
    bitfield! {
        pub struct PS_PROTECTION(u8);
        pub u8, type_, set_type_: 2, 0;   // 3 bits
        pub u8, audit, set_audit: 3;      // 1 bit
        pub u8, signer, set_signer: 7, 4; // 4 bits
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct CallbackRestaure {
        pub index: usize,
        pub callback: Callbacks,
        pub address: u64,
    }

    #[repr(C)]
    pub struct CallbackRestaureOb{
        pub index: usize,
        pub callback: Callbacks,
        pub pre_operation: u64,
        pub post_operation: u64,
        pub entry: u64,
    }
}

pub mod types {
    use super::*; 
    
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

    pub type ZwSuspendThreadType = unsafe extern "system" fn (
        ThreadHandle: HANDLE,
        PreviousSuspendCount: *mut u32,
    ) -> NTSTATUS;

    pub type ZwResumeThreadType = unsafe extern "system" fn(
        ThreadHandle: HANDLE,
        PreviousSuspendCount: *mut u32,
    ) -> NTSTATUS;

    pub type ZwCreateDebugObjectType = unsafe extern "system" fn(
        DebugObjectHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        Flags: BOOLEAN,
    ) -> NTSTATUS;

    pub type ZwDebugActiveProcessType = unsafe extern "system" fn(
        ProcessHandle: HANDLE,
        DebugObjectHandle: HANDLE,
    ) -> NTSTATUS;

    pub type ZwRemoveProcessDebugType = unsafe extern "system" fn(
        ProcessHandle: HANDLE,
        DebugObjectHandle: HANDLE,
    ) -> NTSTATUS;
}

pub mod enums {
    #[repr(C)]
    pub enum KAPC_ENVIROMENT {
        OriginalApcEnvironment,
        AttachedApcEnvironment,
        CurrentApcEnvironment,
        InsertApcEnvironment
    }   
}

extern "system" {
    pub fn PsGetProcessPeb(ProcessId: PEPROCESS) -> PPEB;
   
    pub fn PsGetCurrentThread() -> PETHREAD;
    
    pub fn IoCreateDriver(
        driver_name: PUNICODE_STRING,
        driver_initialize: types::DRIVER_INITIALIZE,
    ) -> NTSTATUS;

    pub fn MmCopyVirtualMemory(
        source_process: PEPROCESS,
        source_address: PVOID,
        target_process: PEPROCESS,
        target_address: PVOID,
        buffer_size: SIZE_T,
        previous_mode: KPROCESSOR_MODE,
        return_size: PSIZE_T,
    );

    pub fn ObReferenceObjectByName(
        object_name: PUNICODE_STRING,
        attributes: u32,
        access_state: PACCESS_STATE,
        desired_access: ACCESS_MASK,
        object_type: POBJECT_TYPE,
        access_mode: KPROCESSOR_MODE,
        parse_context: PVOID,
        object: *mut PVOID,
    );

    pub fn KeRaiseIrql(new_irql: KIRQL, old_irql: PKIRQL);

    pub fn KeInitializeApc(
        apc: PRKAPC,
        thread: PETHREAD,
        environment: enums::KAPC_ENVIROMENT,
        kernel_routine: types::PKKERNEL_ROUTINE,
        rundown_routine: types::PKRUNDOWN_ROUTINE,
        normal_routine: types::PKNORMAL_ROUTINE,
        apc_mode: KPROCESSOR_MODE,
        normal_context: PVOID
    );

    pub fn KeTestAlertThread(
        alert_mode: KPROCESSOR_MODE
    );

    pub fn KeInsertQueueApc(
        apc: PRKAPC,
        system_argument1: PVOID,
        system_argument2: PVOID,
        increment: KPRIORITY
    ) -> bool;

    pub fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG
    ) -> NTSTATUS;

    pub fn ZwOpenThread(
        handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        client_id: *mut CLIENT_ID
    ) -> NTSTATUS;

    pub fn PsGetContextThread(
        Thread: PETHREAD,
        ThreadContext: *mut CONTEXT,
        Mode: KPROCESSOR_MODE
    ) -> NTSTATUS;

    pub fn PsSetContextThread(
        Thread: PETHREAD,
        ThreadContext: *mut CONTEXT,
        Mode: KPROCESSOR_MODE
    ) -> NTSTATUS;
}
