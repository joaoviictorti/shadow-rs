use {
    alloc::boxed::Box,
    hashbrown::HashMap,
    shared::{ioctls::IOCTL_ENUMERATE_MODULE, structs::{ModuleInfo, TargetProcess}},
    wdk_sys::{IO_STACK_LOCATION, IRP},
    crate::{handle_module, module::Module, utils::ioctls::IoctlHandler},
};

pub fn get_module_ioctls(ioctls: &mut HashMap<u32, IoctlHandler>) {
    ioctls.insert(IOCTL_ENUMERATE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION | {
        log::info!("Received IOCTL_ENUMERATE_MODULE");
        let mut information = 0;
        let status = unsafe { handle_module!(irp, stack, Module::enumerate_module, TargetProcess, ModuleInfo, &mut information) };
        unsafe { (*irp).IoStatus.Information = information as u64 };
        status
    }) as IoctlHandler);
}