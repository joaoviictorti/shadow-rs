// Enumerate Modules
#[repr(C)]
#[derive(Debug)]
pub struct ModuleInfo {
    pub address: usize,
    pub name: [u16; 256],
    pub index: u8,
}
