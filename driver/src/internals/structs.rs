use {
    super::*,
    wdk_sys::*,
    core::mem::ManuallyDrop,
    crate::internals::enums::COMUNICATION_TYPE,
    shared::{structs::LIST_ENTRY, enums::Callbacks}
};

pub use vad::*;

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

#[repr(C)]
pub struct NSI_PARAM {
    pub reserved1: usize,
    pub reverved2: usize,
    pub module_id: *mut core::ffi::c_void,
    pub type_: COMUNICATION_TYPE,
    pub reserved3: u32,
    pub reserved4: u32,
    pub entries: *mut core::ffi::c_void,
    pub entry_size: usize,
    pub reserved5: *mut core::ffi::c_void,
    pub reserved6: usize,
    pub status_entries: *mut NSI_STATUS_ENTRY,
    pub reserved7: usize,
    pub process_entries: *mut NSI_PROCESS_ENTRY,
    pub process_entry_size: usize,
    pub count: usize
}

#[repr(C)]
pub struct NSI_STATUS_ENTRY {
    pub state: u32,
    pub reserved: [u8; 8]
}

#[repr(C)]
pub struct NSI_PROCESS_ENTRY {
    pub udp_process_id: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub tcp_process_id: u32,
    pub reserved3: u32,
    pub reserved4: u32,
    pub reserved5: u32,
    pub reserved6: u32
}

#[repr(C)]
#[derive(Debug)]
pub struct NSI_TCP_ENTRY {
    pub reserved1: [u8; 2],
    pub port: u16,
    pub ip_address: u32,
    pub ip_address6: [u8; 16],
    pub reserved2: [u8; 4]
}

#[repr(C)]
#[derive(Debug)]
pub struct NSI_TABLE_TCP_ENTRY {
    pub local: NSI_TCP_ENTRY,
    pub remote: NSI_TCP_ENTRY
}

#[repr(C)]
pub struct NSI_UDP_ENTRY {
    pub reserved1: [u8; 2],
    pub port: u16,
    pub ip_address: u32,
    pub ip_address6: [u8; 16],
    pub reserved2: [u8; 4]
}

#[repr(C)] 
pub struct TRACE_ENABLE_INFO {
    pub is_enabled: u32, 
    pub level: u8, 
    pub reserved1: u8,
    pub loggerid: u16,
    pub enable_property: u32, 
    pub reserved2: u32, 
    pub match_any_keyword: u64,
    pub match_all_keyword: u64
}

