use wdk_sys::{ntddk::{KeStackAttachProcess, KeUnstackDetachProcess}, KAPC_STATE, PRKPROCESS};

pub struct ProcessAttach {
    apc_state: KAPC_STATE,
    attached: bool,
}

impl ProcessAttach {
    // Function for attaching the context of a process
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

    // Method for manually detaching the process
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
    fn drop(&mut self) {
        // If it is still attached, it unattaches when it leaves the scope
        if self.attached {
            unsafe {
                KeUnstackDetachProcess(&mut self.apc_state);
            }
        }
    }
}
