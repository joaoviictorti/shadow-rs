use wdk_sys::*;
use super::*;

extern "C" {
    pub static mut IoDriverObjectType: *mut *mut _OBJECT_TYPE;
}

#[link(name = "ntoskrnl")] 
extern "system" {
    pub fn PsGetProcessPeb(ProcessId: PEPROCESS) -> PPEB;
   
    pub fn PsGetCurrentThread() -> PETHREAD;
    
    pub fn IoCreateDriver(
        driver_name: PUNICODE_STRING,
        driver_initialize: types::DRIVER_INITIALIZE,
    ) -> NTSTATUS;

    pub fn MmCopyVirtualMemory(
        source_process: PEPROCESS,
        source_address: PVOID,
        target_process: PEPROCESS,
        target_address: PVOID,
        buffer_size: SIZE_T,
        previous_mode: KPROCESSOR_MODE,
        return_size: PSIZE_T,
    );

    pub fn ObReferenceObjectByName(
        object_name: PUNICODE_STRING,
        attributes: u32,
        access_state: PACCESS_STATE,
        desired_access: ACCESS_MASK,
        object_type: POBJECT_TYPE,
        access_mode: KPROCESSOR_MODE,
        parse_context: PVOID,
        object: *mut PVOID,
    ) -> NTSTATUS;
    
    pub fn KeInitializeApc(
        apc: PRKAPC,
        thread: PETHREAD,
        environment: enums::KAPC_ENVIROMENT,
        kernel_routine: types::PKKERNEL_ROUTINE,
        rundown_routine: types::PKRUNDOWN_ROUTINE,
        normal_routine: types::PKNORMAL_ROUTINE,
        apc_mode: KPROCESSOR_MODE,
        normal_context: PVOID
    );

    pub fn KeTestAlertThread(
        alert_mode: KPROCESSOR_MODE
    );

    pub fn KeInsertQueueApc(
        apc: PRKAPC,
        system_argument1: PVOID,
        system_argument2: PVOID,
        increment: KPRIORITY
    ) -> bool;

    pub fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG
    ) -> NTSTATUS;

    pub fn ZwOpenThread(
        handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        client_id: *mut CLIENT_ID
    ) -> NTSTATUS;
}
