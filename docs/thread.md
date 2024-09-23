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