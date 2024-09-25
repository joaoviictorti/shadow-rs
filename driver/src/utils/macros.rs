/// A macro to handle I/O operations with input and output buffers.
///
/// This macro abstracts common patterns in handling IOCTL operations, where input and/or output
/// buffers are required. It fetches the buffers from the provided IRP (I/O Request Packet) and
/// passes them to the specified action. If fetching the buffers fails, it immediately returns
/// the failure status.
/// 
#[macro_export]
macro_rules! handle {
    ($irp:expr, $stack:expr, $action:expr, $input_type:ty, $output_type:ty, $information:expr) => {{
        let output_buffer = match crate::utils::get_output_buffer::<$output_type>($irp) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        let input_buffer = match crate::utils::get_input_buffer::<$input_type>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };
        
        $action(input_buffer, output_buffer, $information)
    }};

    ($irp:expr, $action:expr, $type_:ty) => {{
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($irp) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        $action(input_buffer)
    }};

    ($irp:expr, $action:expr, $type_:ty, $information:expr) => {{
        let output_buffer = match crate::utils::get_output_buffer::<$type_>($irp) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        $action(output_buffer, $information)
    }};
}

/// Macro to handle registry-related operations.
///
/// This macro abstracts common patterns in handling IOCTL operations, where input and/or output
/// buffers are required. It fetches the buffers from the provided IRP (I/O Request Packet) and
/// passes them to the specified action. If fetching the buffers fails, it immediately returns
/// the failure status.
/// 
#[cfg(not(feature = "mapper"))]
#[macro_export]
macro_rules! handle_registry {
    ($irp:expr, $action:expr, $type_:ty, $information:expr, $type_registry:ty) => {{
        let output_buffer = match crate::utils::get_output_buffer::<$type_>($irp) {
            Ok(buffer) => buffer, 
            Err(status) => return status,
        };

        $action(output_buffer, $information)
    }};

    ($stack:expr, $action:expr, $type_:ty, $type_registry:expr) => {{
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };
        $action(input_buffer, $type_registry)
    }};
}

/// Macro to handle callback-related operations.
///
/// This macro abstracts common patterns in handling IOCTL operations, where input and/or output
/// buffers are required. It fetches the buffers from the provided IRP (I/O Request Packet) and
/// passes them to the specified action. If fetching the buffers fails, it immediately returns
/// the failure status.
///
#[macro_export]
macro_rules! handle_callback {
    ($irp:expr, $stack:expr, $input_type:ty, $output_type:ty, $information:expr, $ioctl:expr) => {{
        use shared::enums::Callbacks;
        use crate::callback::{callbacks::{notify_routine::Callback, registry::CallbackRegistry, object::CallbackOb}, CallbackList};
        use wdk_sys::STATUS_UNSUCCESSFUL;

        let input_buffer = match crate::utils::get_input_buffer::<$input_type>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        let output_buffer = match crate::utils::get_output_buffer::<$output_type>($irp) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        let status = match $ioctl {
            IOCTL_ENUMERATE_CALLBACK => match (*input_buffer).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine => Callback::enumerate_callback(input_buffer, output_buffer, $information),
                Callbacks::PsSetCreateThreadNotifyRoutine => Callback::enumerate_callback(input_buffer, output_buffer, $information),
                Callbacks::PsSetLoadImageNotifyRoutine => Callback::enumerate_callback(input_buffer, output_buffer, $information),
                Callbacks::CmRegisterCallbackEx => CallbackRegistry::enumerate_callback(input_buffer, output_buffer, $information),
                Callbacks::ObProcess => CallbackOb::enumerate_callback(input_buffer, output_buffer, $information),
                Callbacks::ObThread => CallbackOb::enumerate_callback(input_buffer, output_buffer, $information),
            },
            IOCTL_ENUMERATE_REMOVED_CALLBACK => match (*input_buffer).callback {
                Callbacks::PsSetCreateProcessNotifyRoutine => Callback::enumerate_removed_callback(input_buffer, output_buffer, $information),
                Callbacks::PsSetCreateThreadNotifyRoutine => Callback::enumerate_removed_callback(input_buffer, output_buffer, $information),
                Callbacks::PsSetLoadImageNotifyRoutine => Callback::enumerate_removed_callback(input_buffer, output_buffer, $information),
                Callbacks::CmRegisterCallbackEx => CallbackRegistry::enumerate_removed_callback(input_buffer, output_buffer, $information),
                Callbacks::ObProcess => CallbackOb::enumerate_removed_callback(input_buffer, output_buffer, $information),
                Callbacks::ObThread => CallbackOb::enumerate_removed_callback(input_buffer, output_buffer, $information),
            },
            _ => Err(STATUS_UNSUCCESSFUL)
        };

        status
    }};
    
    ($irp:expr, $type_:ty, $ioctl:expr) => {{
        use shared::enums::Callbacks;
        use crate::callback::{callbacks::{notify_routine::Callback, registry::CallbackRegistry, object::CallbackOb}, CallbackList};
        
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($irp) {
            Ok(buffer) => buffer, 
            Err(status) => return status,
        };

        let mut status = 0;
        match $ioctl {
            IOCTL_REMOVE_CALLBACK => {
                status = match (*input_buffer).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine => Callback::remove_callback(input_buffer),
                    Callbacks::PsSetCreateThreadNotifyRoutine => Callback::remove_callback(input_buffer),
                    Callbacks::PsSetLoadImageNotifyRoutine => Callback::remove_callback(input_buffer),
                    Callbacks::CmRegisterCallbackEx => CallbackRegistry::remove_callback(input_buffer),
                    Callbacks::ObProcess => CallbackOb::remove_callback(input_buffer),
                    Callbacks::ObThread => CallbackOb::remove_callback(input_buffer),
                };
            },
            IOCTL_RESTORE_CALLBACK => {
                status = match (*input_buffer).callback {
                    Callbacks::PsSetCreateProcessNotifyRoutine => Callback::restore_callback(input_buffer),
                    Callbacks::PsSetCreateThreadNotifyRoutine => Callback::restore_callback(input_buffer),
                    Callbacks::PsSetLoadImageNotifyRoutine => Callback::restore_callback(input_buffer),
                    Callbacks::CmRegisterCallbackEx => CallbackRegistry::restore_callback(input_buffer),
                    Callbacks::ObProcess => CallbackOb::restore_callback(input_buffer),
                    Callbacks::ObThread => CallbackOb::restore_callback(input_buffer),
                };
            },
            _ => {}
        }
        
        status
    }};
}
