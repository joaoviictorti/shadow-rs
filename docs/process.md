## Process

## Hide / Unhide Process

Description:
This command allows you to hide or reveal specific processes on the system.

```cmd
shadow.exe process [hide | unhide] --pid <pid>
```

* `hide`: Hide the specified process.
* `unhide`: Unhide the specified process.
* `pid`: The PID of the process you want to hide or reveal.

Example of use:

```cmd
shadow.exe process hide --pid 1234
```

This command will hide the process with PID 1234.


## Elevate Process to System

Description:
This command allows you to raise the process to system.

```cmd
shadow.exe process elevate --pid <pid>
```

* `elevate`: Elevate the process.
* `pid`: The PID of the process you want to escalate to system.

Example of use:

```cmd
shadow.exe process elevate --pid 1234
```

This command will elevate the process with PID 1234.

## Process Signature (PP / PPL)

Description:
This command allows you to protect / unprotect a process using Process Protection (PP) or Protected Process Light (PPL).

```cmd
shadow.exe process signature --pt <protection> --sg <signature> --pid <pid>
```

* `signature`: Signature the process.
* `pt`: The protection type.
    * Possible values:
        - `none`:            No protection
        - `protected-light`: Light protection
        - `protected`:       Full protection

* `sg`: The protection signer.
    *   Possible values:
        - `none`:         No signer
        - `authenticode`: Authenticode signer
        - `code-gen`:     Code generation signer
        - `antimalware`:  Antimalware signer
        - `lsa`:          LSA signer
        - `windows`:      Windows signer
        - `win-tcb`:      WinTcb signer
        - `win-system`:   WinSystem signer
        - `app`:          Application signer
        - `max`:          Maximum value for signers

* `pid`: The PID of the process you want to modify PP / PPL.

Example of use:

```cmd
shadow.exe process signature --pid 1234 --pt protected --sg win-tcb
```

This command changes the protection of the process with PID 1234.

## Terminate Process

Description:
This command allows you to terminate a process.

```cmd
shadow.exe process terminate --pid <pid>
```

* `terminate`: Terminate the specified process.
* `pid`: The PID of the process you want to terminate.

Example of use:

```cmd
shadow.exe process terminate --pid 1234
```

This command will terminate the process with PID 1234.

## Lists protected and hidden processes currently on the system

Description:
This command allows you to list the processes that are currently protected or hidden.

```cmd
shadow.exe process enumerate -l -t <value>
```

* `enumerate`: Terminate the specified process.
* `-l / --list`: List the protected or hidden process.
* `-t / --type`: Specify which type you want to list
    *   Possible values:
        - hide:       List of hidden targets
        - protection: List of protected targets

Example of use:

```cmd
shadow.exe process enumerate -l -t protection
```

This command will close and list the currently protected processes.