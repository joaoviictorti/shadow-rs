use wdk_sys::{ntddk::{KeStackAttachProcess, KeUnstackDetachProcess}, KAPC_STATE, PRKPROCESS};

/// A wrapper for managing the attachment to a process context in the Windows kernel.
///
/// This struct provides a safe abstraction for attaching to the context of a target process using
/// `KeStackAttachProcess` and ensures that the process is properly detached when no longer needed
/// (either manually or automatically when it goes out of scope).
///
/// When a `ProcessAttach` instance is dropped, it will automatically detach from the process
/// if still attached.
pub struct ProcessAttach {
    /// The APC (Asynchronous Procedure Call) state used to manage process attachment.
    apc_state: KAPC_STATE,
    /// Indicates whether the process is currently attached.
    attached: bool,
}

impl ProcessAttach {
    /// Attaches to the context of a target process.
    ///
    /// This function attaches the current thread to the address space of the specified
    /// process using `KeStackAttachProcess`. This allows the current thread to operate within
    /// the target process context.
    ///
    /// # Arguments
    /// 
    /// * `target_process` - A pointer to the target process (`PRKPROCESS`) to attach to.
    ///
    /// # Returns
    /// 
    /// * A new `ProcessAttach` instance representing the attached process context.
    #[inline]
    pub fn new(target_process: PRKPROCESS) -> Self {
        let mut apc_state: KAPC_STATE = unsafe { core::mem::zeroed() };

        unsafe {
            KeStackAttachProcess(target_process, &mut apc_state);
        }

        Self {
            apc_state,
            attached: true,
        }
    }

    /// Manually detaches from the process context.
    ///
    /// This method can be called to explicitly detach the current thread from the target process's
    /// address space, if it was previously attached.
    #[inline]
    pub fn detach(&mut self) {
        if self.attached {
            unsafe {
                KeUnstackDetachProcess(&mut self.apc_state);
            }
            self.attached = false;
        }
    }
}

impl Drop for ProcessAttach {
    /// Automatically detaches from the process context when the `ProcessAttach` instance is dropped.
    ///
    /// This method ensures that the current thread is detached from the target process's address space
    /// when the `ProcessAttach` object goes out of scope. If the process is still attached when `drop`
    /// is called, it will be safely detached using `KeUnstackDetachProcess`.
    fn drop(&mut self) {
        // If it is still attached, it unattaches when it leaves the scope.
        if self.attached {
            unsafe {
                KeUnstackDetachProcess(&mut self.apc_state);
            }
        }
    }
}
