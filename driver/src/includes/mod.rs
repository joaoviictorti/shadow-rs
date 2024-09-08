#![allow(non_camel_case_types)]
#![allow(dead_code)]

use {
    wdk_sys::*, 
    bitfield::bitfield, 
    winapi::ctypes::c_void,
    shared::structs::LIST_ENTRY,
    ntapi::ntpsapi::PPS_ATTRIBUTE_LIST, 
};

pub mod vad;

pub mod structs {
    use super::*;
    use shared::vars::Callbacks;
    use core::mem::ManuallyDrop;

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
    
    bitfield! {
        pub struct PS_PROTECTION(u8);
        pub u8, type_, set_type_: 2, 0;   
        pub u8, audit, set_audit: 3;      
        pub u8, signer, set_signer: 7, 4;
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

    #[repr(C)]
    pub struct MMVAD_SHORT {
        pub vad_node: RTL_BALANCED_NODE,
        pub starting_vpn: u32,
        pub ending_vpn: u32,
        pub starting_vpn_high: u8,
        pub ending_vpn_high: u8,
        pub commit_charge_high: u8,
        pub spare_nt64_vad_uchar: u8,
        pub reference_count: i32,
        pub push_lock: usize,
        pub u: Uunion,
        pub u1: U1Union,
        pub u5: U5Union,
    }

    #[repr(C)]
    pub union Uunion {
        pub long_flags: u32,
        pub vad_flags: ManuallyDrop<MMVAD_FLAGS>,
        pub private_vad_flags: ManuallyDrop<MM_PRIVATE_VAD_FLAGS>,
        pub graphics_vad_flags: ManuallyDrop<MM_GRAPHICS_VAD_FLAGS>,
        pub shared_vad_flags: ManuallyDrop<MM_SHARED_VAD_FLAGS>,
        pub volatile_long: u32,
    }

    #[repr(C)]
    pub union U1Union {
        pub long_flags1: u32,
        pub vad_flags1: ManuallyDrop<MMVAD_FLAGS1>,
    }

    #[repr(C)]
    pub union U5Union {
        pub event_list_ulong_ptr: u64,
        pub starting_vpn_higher: u8,
    }

    bitfield! {
        #[repr(C)]
        pub struct MM_PRIVATE_VAD_FLAGS(u32);
        impl Debug;
        impl Default;
        u32;
        pub lock, set_lock: 1;
        pub lock_contended, set_lock_contended: 1;
        pub delete_in_progress, set_delete_in_progress: 1;
        pub no_change, set_no_change: 1;
        pub vad_type, set_vad_type: 6, 4;
        pub protection, set_protection: 11, 7;
        pub preferred_node, set_preferred_node: 18, 12;
        pub page_size, set_page_size: 19, 20;
        pub private_memory_always_set, set_private_memory: 21;
        pub write_watch, set_write: 22;
        pub fixed_large_page_size, set_page_large: 23;
        pub zero_fill_pages_optional, set_zero_fill: 24;
        pub graphics, set_graphics: 25;
        pub enclave, set_enclave: 26;
        pub shadow_stack, set_shadow_stack: 27;
        pub physical_memory_pfns_referenced, set_physical: 28;
    }

    bitfield! {
        #[repr(C)]
        pub struct MM_SHARED_VAD_FLAGS(u32);
        impl Debug;
        impl Default;
        u32;
        pub lock, set_lock: 1;
        pub lock_contended, set_lock_contended: 1;
        pub delete_in_progress, set_delete_in_progress: 1;
        pub no_change, set_no_change: 1;
        pub vad_type, set_vad_type: 6, 4;
        pub protection, set_protection: 11, 7;
        pub preferred_node, set_preferred_node: 18, 12;
        pub page_size, set_page_size: 19, 20;
        pub private_memory_always_set, set_private_memory: 21;
        pub private_fixup, set_private_fixup: 22;
        pub hot_patch_state, set_hot_patch_state: 24, 23;
    }

    bitfield! {
        #[repr(C)]
        pub struct MMVAD_FLAGS(u32);
        impl Debug;
        u32;
        pub lock, set_lock: 0;
        pub lock_contended, set_lock_contended: 1;
        pub delete_in_progress, set_delete_in_progress: 2;
        pub no_change, set_no_change: 3;
        pub vad_type, set_vad_type: 6, 4;
        pub protection, set_protection: 11, 7;
        pub preferred_node, set_preferred_node: 18, 12;
        pub page_size, set_page_size: 19, 20;
        pub private_memory, set_private_memory: 21;
    }

    bitfield! {
        #[repr(C)]
        pub struct MM_GRAPHICS_VAD_FLAGS(u32);
        impl Debug;
        impl Default;
        u32;
        pub lock, set_lock: 1;
        pub lock_contended, set_lock_contended: 1;
        pub delete_in_progress, set_delete_in_progress: 1;
        pub no_change, set_no_change: 1;
        pub vad_type, set_vad_type: 6, 4;
        pub protection, set_protection: 11, 7;
        pub preferred_node, set_preferred_node: 18, 12;
        pub page_size, set_page_size: 19, 20;
        pub private_memory_always_set, set_private_memory: 21;
        pub write_watch, set_write: 22;
        pub fixed_large_page_size, set_page_large: 23;
        pub zero_fill_pages_optional, set_zero_fill: 24;
        pub graphics_always_set, set_graphics: 25;
        pub graphics_use_coherent, set_graphics_use: 26;
        pub graphics_no_cache, set_graphics_no_cache: 27;
        pub graphics_page_protection, set_graphics_page_protection: 30, 28;
    }
    
    bitfield! {
        #[repr(C)]
        pub struct MMVAD_FLAGS1(u32);
        impl Debug;
        pub commit_charge, set_commit_charge: 30, 0;    
        pub mem_commit, set_mem_commit: 31;
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
}
