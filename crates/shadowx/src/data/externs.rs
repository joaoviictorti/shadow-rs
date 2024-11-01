use super::*;
use wdk_sys::*;

extern "C" {
    pub static mut IoDriverObjectType: *mut *mut _OBJECT_TYPE;
}

extern "system" {
    pub fn PsGetProcessPeb(ProcessId: PEPROCESS) -> PPEB;

    pub fn PsGetCurrentThread() -> PETHREAD;

    pub fn IoCreateDriver(
        DriverName: PUNICODE_STRING,
        DriverInitialize: types::DRIVER_INITIALIZE,
    ) -> NTSTATUS;

    pub fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG
    ) -> NTSTATUS;

    pub fn MmCopyVirtualMemory(
        SourceProcess: PEPROCESS,
        SourceAddress: PVOID,
        TargetProcess: PEPROCESS,
        TargetAddress: PVOID,
        BufferSize: SIZE_T,
        PreviousMode: KPROCESSOR_MODE,
        ReturnSize: PSIZE_T,
    );

    pub fn KeInitializeApc(
        APC: PRKAPC,
        Thread: PETHREAD,
        Environment: enums::KAPC_ENVIROMENT,
        KernelRoutine: types::PKKERNEL_ROUTINE,
        RundownRoutine: types::PKRUNDOWN_ROUTINE,
        NormalRoutine: types::PKNORMAL_ROUTINE,
        ApcMode: KPROCESSOR_MODE,
        NormalContext: PVOID
    );

    pub fn KeTestAlertThread(
        AlertMode: KPROCESSOR_MODE
    );

    pub fn KeInsertQueueApc(
        APC: PRKAPC,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
        Increment: KPRIORITY
    ) -> bool;

    pub fn ObReferenceObjectByName(
        ObjectName: PUNICODE_STRING,
        Attributes: u32,
        AccessState: PACCESS_STATE,
        DesiredAccess: ACCESS_MASK,
        ObjectType: POBJECT_TYPE,
        AccessMode: KPROCESSOR_MODE,
        ParseContext: PVOID,
        Object: *mut PVOID,
    ) -> NTSTATUS;
}
