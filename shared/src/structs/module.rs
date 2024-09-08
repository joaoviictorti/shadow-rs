// Enumerate Modules
#[repr(C)]
#[derive(Debug)]
pub struct ModuleInfo {
    pub address: usize,
    pub name: [u16; 256],
    pub index: u8,
}

// Enumerate Modules
#[repr(C)]
#[derive(Debug)]
pub struct TargetModule {
    pub pid: usize,
    pub module_name: alloc::string::String,
}
