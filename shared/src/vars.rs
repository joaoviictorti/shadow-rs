pub const MAX_PIDS: usize = 256;
pub const MAX_DRIVER: usize = 256;
pub const MAX_TIDS: usize = 256;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Callbacks {
    PsSetCreateProcessNotifyRoutine,
    PsSetCreateThreadNotifyRoutine,
    PsSetLoadImageNotifyRoutine
}

#[derive(Debug)]
pub enum Options {
    Hide,
    Protection
}
