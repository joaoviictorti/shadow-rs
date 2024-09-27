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
    Protection,
}

/// Represents the type of protocol (TCP/UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
}

/// Represents whether the port is local or remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    LOCAL,
    REMOTE,
}