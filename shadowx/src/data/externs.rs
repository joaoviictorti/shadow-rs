use super::*;
use wdk_sys::*;
use ntapi::ntexapi::SYSTEM_INFORMATION_CLASS;
use crate::data::{
    KBUGCHECK_REASON_CALLBACK_RECORD, 
    KBUGCHECK_REASON_CALLBACK_ROUTINE
};

extern "C" {
    pub static mut IoDriverObjectType: *mut *mut _OBJECT_TYPE;
}

extern "system" {
    pub fn PsGetProcessPeb(Process: PEPROCESS) -> PPEB;
    pub fn PsSuspendProcess(Process: PEPROCESS) -> NTSTATUS;
    pub fn PsResumeProcess(Process: PEPROCESS) -> NTSTATUS;
    pub fn PsGetCurrentThread() -> PETHREAD;
    pub fn KeTestAlertThread(AlertMode: KPROCESSOR_MODE);
    pub fn IoCreateDriver(
        DriverName: PUNICODE_STRING,
        DriverInitialize: types::DRIVER_INITIALIZE,
    ) -> NTSTATUS;

    pub fn KeRegisterBugCheckReasonCallback(
        CallbackRecord: *mut KBUGCHECK_REASON_CALLBACK_RECORD,
        CallbackRoutine: KBUGCHECK_REASON_CALLBACK_ROUTINE,
        Reason: KBUGCHECK_CALLBACK_REASON,
        Component: PUCHAR,
    ) -> BOOLEAN;

    pub fn KeDeregisterBugCheckReasonCallback(
        CallbackRecord: *mut KBUGCHECK_REASON_CALLBACK_RECORD,
    ) -> BOOLEAN;

    pub fn KeUserModeCallback(
        ApiIndex: ULONG,
        InputBuffer: PVOID,
        InputLength: ULONG,
        OutputBuffer: *mut PVOID,
        OutputLength: PULONG,
    ) -> NTSTATUS;

    pub fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: PSIZE_T,
        NewProtect: ULONG,
        OldProtect: PULONG,
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
        NormalContext: PVOID,
    );

    pub fn ZwQuerySystemInformation(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;

    pub fn KeInsertQueueApc(
        APC: PRKAPC,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
        Increment: KPRIORITY,
    ) -> bool;

    pub fn PsGetContextThread(
        Thread: PETHREAD,
        ThreadContext: PCONTEXT,
        Mode: KPROCESSOR_MODE,
    ) -> NTSTATUS;

    pub fn PsSetContextThread(
        Thread: PETHREAD,
        ThreadContext: PCONTEXT,
        Mode: KPROCESSOR_MODE,
    ) -> NTSTATUS;

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
