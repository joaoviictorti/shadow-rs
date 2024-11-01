# shadow-rs 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![Forks](https://img.shields.io/github/forks/joaoviictorti/shadow-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/shadow-rs)
![License](https://img.shields.io/github/license/joaoviictorti/shadow-rs)

`shadow-rs` is a Windows kernel rootkit written in Rust, demonstrating advanced techniques for kernel manipulation while leveraging Rust’s safety and performance features. This project is intended for educational and research purposes.

The project also provides useful crates for developing rootkits, such as shadowx, which consolidates core logic and essential techniques. It includes rootkit-specific tricks, with plans for additional features in future updates.

## Table of Contents

* [Legal notice](#legal-notice)
* [Features](#features)
* [Documentation](#documentation)
* [Crates](#crates)
* [Installation](#installation)
* [Supported Platforms](#supported-Platforms)
* [Build Instructions](#build-instructions)
  * [Driver](#driver)
  * [Client](#client)
* [Setup Instructions](#setup-instructions)
  * [Enable Test Mode](#enable-test-mode)
  * [Debug via Windbg](#debug-via-windbg)
  * [Create/Start Service](#createstart-service)
* [Contributing to shadow-rs](#contributing-to-shadow-rs)
* [Credits / References](#credits--references)
* [License](#license)

## Legal Notice

> [!IMPORTANT]  
> This project is under development.
> This project is for educational and research purposes. Malicious use of the software is strictly prohibited and discouraged. I am not responsible for any damage caused by improper use of the software.

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
    - ✅ Enable Keylogger

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

### Port

- ✅ Ports (Hide / Unhide)

### Module

- ✅ Hide Module
- ✅ Enumerate Module 

### Registry

- ✅ Key and Values (Hide / Unhide) 
- ✅ Registry Protection (Anti-Deletion e Overwriting) 

### Injection

- ✅ Process Injection - Shellcode (ZwCreateThreadEx)
- ✅ Process Injection - DLL (ZwCreateThreadEx) 
- ✅ APC Injection - Shellcode

## Documentation

If you would like to read the documentation on how to use the tool, simply navigate to the `/docs` folder. There you will find detailed information on setting up, using, and contributing to the project.

## Crates

shadow-rs offers some useful crates for developing rootkits, such as [**shadowx**](/crates/shadowx/). This crate brings together all the logic of the essential techniques and contains some rootkit-specific tricks, with more features planned for future updates.

## Installation
- Install Rust from [**here**](https://www.rust-lang.org/learn/get-started).
- Then follow the instructions provided by [**microsoft**](https://github.com/microsoft/windows-drivers-rs?tab=readme-ov-file#getting-started)

## Supported Platforms
- ✅ Windows 10 / 11 (x64)

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

## Contributing to shadow-rs
To contribute to shadow-rs, follow these steps:

1. Fork this repository.
2. Create a branch: ```git checkout -b <branch_name>```.
3. Make your changes and confirm them: ```git commit -m '<commit_message>'```.
4. Send to the original branch: ```git push origin <project_name> / <local>```.
5. Create the pull request.

Alternatively, consult the GitHub documentation on how to create a pull request.

## Credits / References

- https://leanpub.com/windowskernelprogrammingsecondedition
- https://www.youtube.com/watch?v=t7Rx3crobZU&pp=ugMICgJwdBABGAHKBRBibGFja2hhdCByb290a2l0
- https://github.com/memN0ps/eagle-rs
- https://www.amazon.com/Rootkits-Bootkits-Reversing-Malware-Generation/dp/1593277164
- https://github.com/Idov31/Nidhogg
- https://www.unknowncheats.me/
- https://www.amazon.com.br/Rootkit-Arsenal-Escape-Evasion-Corners/dp/144962636X
- https://github.com/eversinc33/Banshee
- https://synzack.github.io/Blinding-EDR-On-Windows/
- https://github.com/JKornev/hidden
- https://www.amazon.com.br/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319
- https://github.com/mirror/reactos
- https://github.com/Kharos102/ReadWriteDriverSample
- https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-4-16c47b89e826

## License

This project is licensed under the [**MIT License**](/LICENSE)