# syshook

A tool to run scripts and functions in response to syscalls and other events on
a hooked program.

This tool is a WIP, but is intended to allow diagnostic scripts and fault injection
scripts to be written for testing applications.

Scripts are written in the [Janet](https://janet-lang.org/) programming language.

## Examples

hook the 'open-at' syscall

```
syshook -e (sys-enter 257 (eprintf "open-at: path=%s" (arg-string 1))) -- cat ./hello
```
