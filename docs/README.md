## Windows Kernel Rootkit in Rust (shadow-rs) Documentation 🦀

This document presents an overview of the `shadow-rs` project, describing its features, instructions for use and details of the development process. `shadow-rs` is designed to provide an advanced set of tools for manipulating processes, threads, drivers and much more in the Windows kernel.

### Table of contents

* [Process](/docs/process.md)
  * [Hide / Unhide Process](/docs/process.md#hide--unhide-process)
  * [Elevate Process to System](/docs/process.md#elevate-process-to-system)
  * [Process Signature (PP / PPL)](/docs/process.md#process-signature-pp--ppl)
  * [Terminate Process](/docs/process.md#terminate-process)
  * [Lists protected and hidden processes currently on the system](/docs/process.md#lists-protected-and-hidden-processes-currently-on-the-system)

* [Thread](/docs/thread.md)
  * [Hide / Unhide Thread](/docs/thread.md)
  * [Thread Protection (Anti-Kill)](/docs/thread.md)
  * [Lists protected and hidden threads currently on the system](/docs/thread.md)

* [Driver](/docs/driver.md)
    * [Driver (Hide / Unhide)](/docs/driver.md)
    * [Enumerate Driver](/docs/driver.md)    

* [Misc](/docs/misc.md)
    * [Driver Signature Enforcement (DSE) Enable / Disable](/docs/misc.md)
    * [Keylogger Start / Stop](/docs/misc.md)
    * [ETWTI Enable / Disable](/docs/misc.md)

* [Callbacks](/docs/callback.md)
    * [List / Remove / Restore Callbacks](/docs/callback.md)
    * [Listing currently removed callbacks](/docs/callback.md)

* [Module](/docs/module.md)
    * [Hide Module](docs/module.md)
    * [Enumerate Module](/docs/module.md)

* [Registry](/docs/registry.md)
    * [Hide Key and Values](/docs/registry.md)
    * [Registry Protection](/docs/registry.md)

* [Injection](/docs/registry.md)
    * [Process Injection - Shellcode / DLL (ZwCreateThreadEx)](/docs/injection.md)
    * [APC Injection - Shellcode](/docs/injection.md)