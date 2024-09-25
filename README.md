# Windows Kernel Rootkit in Rust (shadow-rs) 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![Forks](https://img.shields.io/github/forks/joaoviictorti/shadow-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/shadow-rs)
![License](https://img.shields.io/github/license/joaoviictorti/shadow-rs)

**shadow-rs** is a Windows kernel rootkit written in Rust, demonstrating advanced techniques for kernel manipulation, while leveraging Rust’s safety and performance features. This project is intended for educational and research purposes.

## Table of Contents

* [Legal notice](#legal-notice)
* [Documentation](#documentation)
* [Features](#contents)
* [Others](#others)
* [Build Instructions](#build-instructions)
  * [Driver](#driver)
  * [Client](#client)
* [Setup Instructions](#setup-instructions)
  * [Enable Test Mode](#enable-test-mode)
  * [Debug via Windbg](#debug-via-windbg)
  * [Create/Start Service](#createstart-service)
* [Upcoming Features](#upcoming-Features)
* [Contributing to shadow-rs](#contributing-to-shadow-rs)
* [License](#license)

## Legal Notice

> [!IMPORTANT]  
> This project is under development.
> This project is for educational and research purposes. Malicious use of the software is strictly prohibited and discouraged. I am not responsible for any damage caused by improper use of the software.

## Documentation

If you would like to read the documentation on how to use the tool, simply navigate to the `/docs` folder. There you will find detailed information on setting up, using, and contributing to the project.

## Features
 
### Process
- ✅ Process (Hide / Unhide) 
- ✅ Process Signature (PP / PPL) 
- ✅ Process Protection (Anti-Kill / Dumping) 
- ✅ Elevate Process to System 
- ✅ Terminate Process 
- ✅ Lists protected and hidden processes currently on the system 

### Thread
- ✅ Thread (Hide / Unhide) 
- ✅ Thread Protection (Anti-Kill) 
- ✅ Lists protected and hidden threads currently on the system 
 
### Driver
- ✅ Driver (Hide / Unhide) 
- ✅ Enumerate Driver 
 
### Misc

  - Driver Signature Enforcement (DSE)
    - ✅ DSE (Enable / Disable) 
  
  - Keylogger
    - ✅ Keylogger (Start / Stop) 

  - ETWTI
    - ✅ ETWTI (Enable / Disable) 

### Callbacks
- ✅ List / Remove / Restore Callbacks 
  - PsSetCreateProcessNotifyRoutine 
  - PsSetCreateThreadNotifyRoutine 
  - PsSetLoadImageNotifyRoutine 
  - CmRegisterCallbackEx  
  - ObRegisterCallbacks (PsProcessType / PsThreadType) 
- ✅ Listing currently removed callbacks 

### Module
- ✅ Hide Module
- ✅ Enumerate Module 

### Registry
- ✅ Hide Key and Values 
- ✅ Registry Protection (Anti-Deletion e Overwriting) 

### Injection
- ✅ Process Injection - Shellcode / DLL (ZwCreateThreadEx) 
- ✅ APC Injection - Shellcode 

## Others

The following functionalities are not "features", they are basically techniques that may be of interest to you to explore, understand and apply in the development of your driver.

- Searching for a "Zw" api not exported from `ntoskrnl.exe` at runtime.
- Reflective Loading.
- Support for mapping the driver in memory.

## Build Instructions

To build the project, ensure you have the Rust toolchain installed. 

#### Driver
To build the driver, first go to the `driver` folder and then run the following command (When you do the first build you have to be as administrator, but after that you won't need to):
```sh
cargo make default --release
```

This driver can be mapped using `kdmapper` among other exploit tools, for example, to put mapping support, use the command:
```sh
cargo make default --release --features mapper
```

#### Client
To build the client, first go into the `client` folder, then run the following command:
```sh
cargo build --release
```

Since some features of the rootkit are not supported due to the controller mapping, use the following command to build the client with only the commands that can be executed with the mapping:
```sh
cargo build --release --features mapper
```

## Setup Instructions

#### Enable Test Mode or Test Signing Mode 

```
bcdedit /set testsigning on
```

#### [Optional] Debug via Windbg

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP> port:<PORT>
```

#### Create / Start Service

You can use [Service Control Manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager) or [OSR Driver Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) to load your driver.

## Upcoming Features 🚧

Stay tuned for new features! Some upcoming highlights:

* ❌ Hide Ports
* ❌ File/Directory Hiding / Anti-Deletion and Overwriting 
* ❌ Minifilters for Callbacks
* ❌ APC Injection - DLL

## Contributing to shadow-rs
To contribute to shadow-rs, follow these steps:

1. Fork this repository.
2. Create a branch: ```git checkout -b <branch_name>```.
3. Make your changes and confirm them: ```git commit -m '<commit_message>'```.
4. Send to the original branch: ```git push origin <project_name> / <local>```.
5. Create the pull request.

Alternatively, consult the GitHub documentation on how to create a pull request.

## License

Licensed under either of [The MIT License](/LICENSE) at your option.