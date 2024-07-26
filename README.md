# Windows Kernel Rootkit in Rust (shadow-rs) 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![Forks](https://img.shields.io/github/forks/joaoviictorti/shadow-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/shadow-rs)
![License](https://img.shields.io/github/license/joaoviictorti/shadow-rs)

## Summary

* [Notice](#notice)
* [Legal notice](#legal-notice)
* [Overview](#overview)
* [Features](#contents)
* [Build Instructions](#build-instructions)
  * [Driver](#driver)
  * [Client](#client)
* [Setup Instructions](#setup-instructions)
  * [Enable Test Mode](#enable-test-mode)
  * [Debug via Windbg](#debug-via-windbg)
  * [Create/Start Service](#createstart-service)
* [Upcoming Features](#upcoming-Features)
* [Credits / References](#references)

## Notice

> [!WARNING]
> This project is under development.

## Legal Notice

> [!WARNING]  
> This project is for educational and research purposes. Malicious use of the software is strictly prohibited and discouraged. I am not responsible for any damage caused by improper use of the software.

## Overview

This project, called shadow-rs, is designed to create a rootkit in the Windows kernel using the Rust language. The aim is to demonstrate advanced techniques for developing rootkits, taking advantage of the security and performance features of the Rust language.
## Features
 
#### Process
- Process (Hide / Unhide) ✅
- Process Signature (PP / PPL) ✅
- Process Protection (Anti-Kill / Dumping) ✅
- Elevate Process to System ✅
- Terminate Process ✅
- Lists protected and hidden processes currently on the system ✅

#### Thread
- Thread (Hide / Unhide) ✅
- Thread Protection (Anti-Kill) ✅
- Lists protected and hidden threads currently on the system ✅
 
#### Driver
- Driver (Hide / Unhide) ✅
- Enumerate Driver ✅
 
#### Driver Signature Enforcement
- DSE (Enable / Disable) ✅
 
#### Keylogger
- Keylogger (Start / Stop) ✅
 
#### Callbacks
- List / Remove / Restore Callbacks 
  - PsSetCreateProcessNotifyRoutine ✅
  - PsSetCreateThreadNotifyRoutine ✅
  - PsSetLoadImageNotifyRoutine ✅

#### Module
- Enumerate Module ✅

#### Registry
- Registry Protection (Anti-Deletion e Overwriting) ✅

## Build Instructions

To build the project, ensure you have the Rust toolchain installed. 

#### Driver
To build the driver, first go into the `driver` folder, then run the following command:
```sh
cargo make default --release
```

This driver can be manually mapped using `kdmapper`, for example, to put the mapping support, use the command:
```sh
cargo make default --release --features mapper
```

#### Client
To build the client, first go into the `client` folder, then run the following command:
```sh
cargo build --releease
```

Since some rootkit features are not supported due to manual driver mapping, use the following command to build the client with only the commands that can be performed with manual mapping:
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

## Upcoming Features

These are some of the features that will be added, but there are many more on the way

#### Callbacks
- CmRegisterCallbackEx ❌
- ObRegisterCallbacks ❌

#### Registry
- Hide Key and Values ❌

#### Module
- Hide Module ❌
 
#### Port
- Hide port ❌
#### File
- Hide File / Directory ❌
- Anti-Deletion e Overwriting ❌
 
#### Injection
- APC ❌
- NtCreateThreadEx ❌

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