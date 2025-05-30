# shadow-rs 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![Forks](https://img.shields.io/github/forks/joaoviictorti/shadow-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/shadow-rs)
![License](https://img.shields.io/github/license/joaoviictorti/shadow-rs)

<p align="center">
    <img height="450" alt="shadow-rs" src="shadow.png">
</p>

`shadow-rs` is a Windows kernel rootkit written in Rust, demonstrating advanced techniques for kernel manipulation while leveraging Rust’s safety and performance features. This project is intended for educational and research purposes.

The project also provides useful crates for developing rootkits, such as [**shadowx**](/shadowx/), which consolidates core logic and essential techniques. It includes rootkit-specific tricks, with plans for additional features in future updates.

The documentation on how to execute CLI commands can be found on the [**Wiki**](https://github.com/joaoviictorti/shadow-rs/wiki)

## Table of Contents

* [Notice](#legal-notice)
* [Features](#features)
* [Installation](#installation)
* [Supported Platforms](#supported-Platforms)
* [Build Instructions](#build-instructions)
  * [Driver](#driver)
  * [Client](#client)
* [Setup Instructions](#setup-instructions)
  * [Enable Test Mode](#enable-test-mode)
  * [Debug via Windbg](#debug-via-windbg)
  * [Create/Start Service](#createstart-service)
* [Disclaimer](#disclaimer)
* [Contributing to shadow-rs](#contributing-to-shadow-rs)
* [References](#references)
* [License](#license)
* [Contributors](#contributors)

## Notice

> [!IMPORTANT]  
> This project is under development.

## Features
 
### Process Features

- ✅ Hide and unhide processes.
- ✅ Modify process signature levels to handle `Protected Processes (PP)` and `Protected Process Light (PPL)`.
- ✅ Protect processes against termination and memory dumping.
- ✅ Elevate process privileges to SYSTEM, granting full administrative access.
- ✅ Terminate target processes.
- ✅ List all protected and hidden processes.

### Thread Features

- ✅ Hide and unhide threads.
- ✅ Protect threads from termination or suspension.
- ✅ List all protected and hidden threads

### Driver Features

- ✅ Hide and unhide kernel-mode drivers.
- ✅ Enumerate all loaded drivers.
- ✅ Enable or disable Driver Signature Enforcement (`DSE`) to allow loading of unsigned drivers.
- ✅ Blocking Driver Loading.

### Callback Features

- ✅ List registered callbacks for process creation, thread creation, image loading, and registry operations.
- ✅ Remove or restore specific callbacks.
- ✅ List all removed callbacks.

### Misc Features

- ✅ Capture keystrokes from user input in real-time with kernel-level interception.
- ✅ Disable Microsoft-Windows-Threat-Intelligence (`EtwTi`).
- ✅ Cleaning Driver Artifacts from Memory Dumps in Case of BSOD.
- ✅ Compile Encryption String.
- ✅ Support for Reflective Driver Loading.

### User Mode Code Execution

- ✅ Inject shellcode or DLLs into processes using `ZwCreateThreadEx`.
- ✅ Asynchronous Procedure Call (`APC`) injection to execute shellcode or DLLs in alertable threads.
- ✅ Execute shellcode in processes using `Thread Hijacking`.

### Module Features

- ✅ Hide modules from process memory listings.
- ✅ Enumerate all loaded modules.

### Registry Features

- ✅ Hide and unhide registry keys and values to prevent detection and manipulation.
- ✅ Apply registry protection to prevent key or value deletion or overwriting.

### Network Features

- ✅ Hide and unhide network ports from netstat and similar monitoring tools.

## Installation

* Install Rust from [**here**](https://www.rust-lang.org/learn/get-started).
* Follow [Microsoft's guide](https://github.com/microsoft/windows-drivers-rs?tab=readme-ov-file#getting-started) to set up Rust for kernel development. 

## Supported Platforms

- ✅ Windows 10 / 11 (x64 only)

## Build Instructions

#### Driver

Navigate to the [driver](/driver) directory and build the kernel driver:

```cmd
cargo make default --release
```

> [!IMPORTANT]  
> Note: The first build must be executed as Administrator. Subsequent builds do not require elevated privileges.

To enable mapping support for tools like kdmapper, compile with:
```cmd
cargo make default --release --features mapper
```

#### Client

Navigate to the [client](/client) directory and build the user-mode client:
```cmd
cargo build --release
```

For compatibility with mapped drivers:
```cmd
cargo build --release --features mapper
```

## Setup Instructions

#### Enable Test Mode or Test Signing Mode 

```
bcdedit /set testsigning on
```

#### Create / Start Service

You can use [Service Control Manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager) or [OSR Driver Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) to load your driver.

## Debugging 

Use Windbg to attach to the kernel and monitor driver activity.

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP> port:<PORT>
```

## Contributing to shadow-rs
To contribute to `shadow-rs`, follow these steps:

1. Fork this repository.
2. Create a branch: ```git checkout -b <branch_name>```.
3. Make your changes and confirm them: ```git commit -m '<commit_message>'```.
4. Send to the original branch: ```git push origin <project_name> / <local>```.
5. Create the pull request.

Alternatively, consult the [**GitHub documentation**](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests) on how to create a pull request.

## Disclaimer

This project is for educational and research purposes. Malicious use of the software is strictly prohibited and discouraged. I am not responsible for any damage caused by improper use of the software.

## References

I want to express my gratitude to these projects that inspired me to create `shadow-rs` and contribute with some features:

* [Hidden](https://github.com/JKornev/hidden)
* [Nidhogg](https://github.com/Idov31/Nidhogg)
* [eagle-rs](https://github.com/memN0ps/eagle-rs)
* [Banshee](https://github.com/eversinc33/Banshee)
* [ReadWriteDriverSample](https://github.com/Kharos102/ReadWriteDriverSample)

### Other Essential Resources:

These materials and research have been invaluable in deepening my understanding of Windows kernel development:

* [UnKnoWnCheaTs](https://www.unknowncheats.me)
* [Reactos](https://github.com/mirror/reactos)
* [Blinding EDR On Windows](https://synzack.github.io/Blinding-EDR-On-Windows)
* [Windows Kernel Programming - Pavel](https://leanpub.com/windowskernelprogrammingsecondedition)
* [Rootkit Arsenal Escape Evasion Corners](https://www.amazon.com.br/Rootkit-Arsenal-Escape-Evasion-Corners/dp/144962636X) 
* [Rootkits Subverting Windows Greg Hoglund](https://www.amazon.com.br/Rootkits-Subverting-Windows-Greg-Hoglund/dp/032129431)
* [Rootkits Bootkits Reversing Malware Generation](https://www.amazon.com/Rootkits-Bootkits-Reversing-Malware-Generation/dp/1593277164)
* [Memory Forensics](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-4-16c47b89e826)
* [Leveraging Rootkits for Post-Exploitation - Black Hat](https://www.youtube.com/watch?v=t7Rx3crobZU&pp=ugMICgJwdBABGAHKBRBibGFja2hhdCByb290a2l0)

## License

This project is licensed under the [**MIT License**](/LICENSE). See the LICENSE file for details.

## Contributors

[![contributors](https://contrib.rocks/image?repo=joaoviictorti/shadow-rs) ](https://github.com/joaoviictorti/shadow-rs/graphs/contributors)