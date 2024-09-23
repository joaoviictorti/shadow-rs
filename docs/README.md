## Windows Kernel Rootkit in Rust (shadow-rs) Documentation

This documentation provides an overview of the shadow-rs rootkit project and instructions on its usage, features, and development process.


### Process

#### Hide / Unhide Process

Description:
This command allows you to hide or reveal specific processes on the system.

```cmd
shadow.exe process [hide | unhide] --pid <pid>
```

* `hide`: Hide the specified process.
* `unhide`: Unhide the specified process.
* `<pid>`: The PID of the process you want to hide or reveal.

Example of use:

```cmd
shadow.exe process hide --pid 1234
```

This command will hide the process with PID 1234.

#### Elevate Process to System

Description:
This command allows you to raise the process to system.

```cmd
shadow.exe process elevate --pid <pid>
```

* `elevate`: Elevate the process
* `<pid>`: The PID of the process you want to escalate to system.

Example of use:

```cmd
shadow.exe process elevate --pid 1234
```

This command will hide the process with PID 1234.