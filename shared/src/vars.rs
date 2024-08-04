pub const MAX_PIDS: usize = 256;
pub const MAX_DRIVER: usize = 256;
pub const MAX_TIDS: usize = 256;

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum Callbacks {
    #[default]
    PsSetCreateProcessNotifyRoutine,
    PsSetCreateThreadNotifyRoutine,
    PsSetLoadImageNotifyRoutine,
    CmRegisterCallbackEx,
    ObProcess,
    ObThread,
}

#[derive(Debug)]
pub enum Options {
    Hide,
    Protection
}
