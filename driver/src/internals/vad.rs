use {
    bitfield::bitfield,
    wdk_sys::LIST_ENTRY,
    super::structs::MMVAD_SHORT,
    core::{ffi::c_void, mem::ManuallyDrop},
};

#[repr(C)]
pub struct MMVAD {
    core: MMVAD_SHORT,
    u2: U2Union,
    pub subsection: *mut SUBSECTION
}

#[repr(C)]
pub union U2Union {
    long_flags2: u32,
    vad_flags2: ManuallyDrop<MMVAD_FLAGS2>
}

bitfield! {
    #[repr(C)]
    pub struct MMVAD_FLAGS2(u32);
    impl Debug;
    u32;
    pub file_offset, set_file_offset: 0, 23;       // 24 bits
    pub large, set_large: 24;                      // 1 bit
    pub trim_behind, set_trim_behind: 25;          // 1 bit
    pub inherit, set_inherit: 26;                  // 1 bit
    pub no_validation_needed, set_no_validation_needed: 27;  // 1 bit
    pub private_demand_zero, set_private_demand_zero: 28;    // 1 bit
    pub spare, set_spare: 29, 31;                  // 3 bits
}

#[repr(C)]
pub struct SUBSECTION {
    pub control_area: *mut CONTROL_AREA,
}

#[repr(C)]
pub union LIST_OR_AWE_CONTEXT {
    list_head: LIST_ENTRY,
    awe_context: *mut c_void,
}

#[repr(C)]
pub union UUnion {
    long_flags: u32,
    flags: u32,
}

#[repr(C)]
pub union U1Union {
    long_flags: u32,
    flags: u32,
}

#[repr(C)]
pub struct CONTROL_AREA {
    segment: *mut *mut c_void,
    list_or_awe_context: LIST_OR_AWE_CONTEXT,
    number_of_section_references: u64,
    number_of_pfn_references: u64,
    number_of_mapped_views: u64,
    number_of_user_references: u64,
    u: UUnion,
    u1: U1Union,
    pub file_pointer: EX_FAST_REF
}

#[repr(C)]
pub union EX_FAST_REF_INNER {
    pub object: *mut c_void,  
    pub value: u64,
}

bitfield! {
    #[repr(C)]
    pub struct ExFastRef(u64);
    impl Debug;

    pub ref_cnt, set_ref_cnt: 0, 3;
}

#[repr(C)]
pub struct EX_FAST_REF {
    pub inner: EX_FAST_REF_INNER,
}