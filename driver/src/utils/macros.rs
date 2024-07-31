/// Macro to handle process-related IRP (I/O Request Packet) operations.
///
/// Matches the input buffer type and executes the given action, returning the status.
#[macro_export]
macro_rules! handle_process {
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

    ($irp:expr, $action:expr, $type_:ty, $information:expr) => {
        let output_buffer = match crate::utils::get_output_buffer::<$type_>($irp) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        }

        $action(output_buffer, $information)
    };
}

/// Macro to handle thread-related IRP (I/O Request Packet) operations.
///
/// Matches the input buffer type and executes the given action, returning the status.
#[macro_export]
macro_rules! handle_thread {
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
}

/// Macro to handle driver-related operations.
///
/// Executes the given action based on the provided parameters and returns the status.
#[macro_export]
macro_rules! handle_driver {
    ($irp:expr, $action:expr, $type_:ty, $information:expr) => {{
        let output_buffer = match crate::utils::get_output_buffer::<$type_>($irp) {
            Ok(buffer) => buffer, 
            Err(status) => return status,
        };

        $action(output_buffer, $information)
    }};

    ($stack:expr, $action:expr, $type_:ty) => {{
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        $action(input_buffer)
    }};
}

/// Macro to handle injection-related operations.
///
/// Executes the given action based on the provided parameters and returns the status.
#[macro_export]
macro_rules! handle_injection {
    ($stack:expr, $action:expr, $type_:ty) => {{
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        $action(input_buffer)
    }};

    ($action:expr) => {
        $action()
    }
}

/// Macro to handle registry-related operations.
///
/// Executes the given action based on the provided parameters and returns the status.
#[cfg(not(feature = "mapper"))]
#[macro_export]
macro_rules! handle_registry {
    ($irp:expr, $action:expr, $type_:ty, $information:expr) => {{
        let output_buffer = match crate::utils::get_output_buffer::<$type_>($irp) {
            Ok(buffer) => buffer, 
            Err(status) => return status,
        };

        $action(output_buffer, $information)
    }};

    ($stack:expr, $action:expr, $type_:ty) => {{
        let input_buffer = match crate::utils::get_input_buffer::<$type_>($stack) {
            Ok(buffer) => buffer,
            Err(status) => return status,
        };

        $action(input_buffer)
    }};
}

/// Macro to handle module-related operations.
///
/// Executes the given action based on the provided parameters and returns the status.
#[macro_export]
macro_rules! handle_module {
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
}

/// Macro to handle callback-related operations.
///
/// Executes the given action based on the provided parameters and returns the status.
#[macro_export]
macro_rules! handle_callback {
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
}
