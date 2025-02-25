/// Represents different types of callbacks available in the system.
///
/// These callbacks are used to monitor or intercept specific events in the system,
/// such as process creation, thread creation, image loading, and more.
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum Callbacks {
    #[default]
    /// The default callback type for process creation events.
    PsSetCreateProcessNotifyRoutine,

    /// Callback for thread creation events.
    PsSetCreateThreadNotifyRoutine,

    /// Callback for image loading events.
    PsSetLoadImageNotifyRoutine,

    /// Callback for registry operations (using `CmRegisterCallbackEx`).
    CmRegisterCallbackEx,

    /// Callback related to process object operations (using `ObRegisterCallbacks`).
    ObProcess,

    /// Callback related to thread object operations (using `ObRegisterCallbacks`).
    ObThread,
}

/// Defines different operational modes or options for controlling behavior.
///
/// These options represent different modes or actions that can be applied to a process
/// or thread, such as hiding it or enabling protection mechanisms.
#[derive(Debug, Default)]
pub enum Options {
    /// Option to hide the process or thread.
    #[default]
    Hide,

    /// Option to apply protection to the process or thread.
    Protection,
}

/// Represents the type of protocol used in network communication (TCP/UDP).
///
/// This enum is used to distinguish between the two most common transport layer protocols:
/// Transmission Control Protocol (TCP) and User Datagram Protocol (UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Transmission Control Protocol (TCP), which is connection-oriented and reliable.
    TCP,

    /// User Datagram Protocol (UDP), which is connectionless and less reliable.
    UDP,
}

/// Represents whether the port is local or remote in the context of network communication.
///
/// This enum is used to categorize a port based on its locality, either representing a
/// local port or a remote port, often used for networking applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    /// Represents a local port on the current machine.
    LOCAL,

    /// Represents a remote port on a different machine.
    REMOTE,
}
