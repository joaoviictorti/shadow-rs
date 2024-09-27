use alloc::vec::Vec;
use spin::{Mutex, lazy::Lazy};
use shared::{
    vars::MAX_PORT,
    structs::PortInfo
};
use wdk_sys::{NTSTATUS, STATUS_DUPLICATE_OBJECTID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// List of protected ports, synchronized with a mutex.
pub static PROTECTED_PORTS: Lazy<Mutex<Vec<PortInfo>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_PORT)));

/// Method to toggle the addition or removal of a port from the list of protected ports.
///
/// # Parameters
/// 
/// - `port`: `PortInfo` structure with information about the port to be added or removed.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
pub fn add_remove_port_toggle(port: *mut PortInfo) -> NTSTATUS {
    if (unsafe { *port }).enable {
        add_target_port(port)
    } else {
        remove_target_port(port)
    }
}

/// Method to add a port to the list of protected ports.
///
/// # Parameters
/// 
/// - `port`: `PortInfo` structure with information about the port to be protected.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
fn add_target_port(port: *mut PortInfo) -> NTSTATUS {
    let mut ports = PROTECTED_PORTS.lock();
    let port = unsafe { *port };

    if ports.len() >= 100 {
        log::error!("Port list is full");
        return STATUS_UNSUCCESSFUL;
    }

    if ports.contains(&port) {
        log::warn!("Port {:?} already exists in the list", port);
        return STATUS_DUPLICATE_OBJECTID;
    }

    ports.push(port);

    STATUS_SUCCESS
}

/// Method to remove a port from the list of protected ports.
///
/// # Parameters
/// 
/// - `port`: `PortInfo` structure with information about the port to be removed.
///
/// # Returns
/// 
/// - `NTSTATUS`: A status code indicating the success or failure of the operation.
/// 
fn remove_target_port(port: *mut PortInfo) -> NTSTATUS {
    let mut ports = PROTECTED_PORTS.lock();
    (unsafe { *port }).enable = true;

    if let Some(index) = ports.iter().position(|&p| p == unsafe { *port }) {
        ports.remove(index);
        STATUS_SUCCESS
    } else {
        log::error!("Port {:?} not found in the list", port);
        STATUS_UNSUCCESSFUL
    }
}

///
/// 
/// 
/// 
/// 
pub fn check_port(port: PortInfo) -> bool {
    PROTECTED_PORTS.lock().contains(&port)
}