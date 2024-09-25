use wdk_sys::{ntddk::{ExFreePool, PsIsThreadTerminating}, PKAPC, PVOID, _MODE::UserMode};
use crate::internals::{
    types::PKNORMAL_ROUTINE, 
    externs::{KeTestAlertThread, PsGetCurrentThread}
};

pub unsafe extern "system" fn kernel_apc_callback(
    apc: PKAPC,
    _normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID
) {

    KeTestAlertThread(UserMode as i8);
    ExFreePool(apc as _)
}

pub unsafe extern "system" fn user_apc_callback(
    apc: PKAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID
) {
    if PsIsThreadTerminating(PsGetCurrentThread()) == 1 {
        *normal_routine = None;
    }

    ExFreePool(apc as _)
}