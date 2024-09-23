## Thread

## Hide / Unhide thread

Description:
This command allows you to hide or reveal specific threads on the system.

```cmd
shadow.exe thread [hide | unhide] --tid <tid>
```

* `hide`: Hide the specified thread.
* `unhide`: Unhide the specified thread.
* `tid`: The TID of the thread you want to hide or reveal.

Example of use:

```cmd
shadow.exe thread hide --tid 1234
```

This command will hide the thread with TID 1234.

## Thread Protection (Anti-Kill)

Description:
This command allows you to add or remove thread protection.

```cmd
shadow.exe thread protection --tid <tid> [--add | --remove]
```

* `protection`: Protect the specified thread.
* `-a / --add`: Add the thread.
* `-r / --remove`: Remove the thread.
* `tid`: The TID of the thread you want to protect.

Example of use:

```cmd
shadow.exe thread protection --tid 1234 --add
```

This command will protect the thread with TID 1234.