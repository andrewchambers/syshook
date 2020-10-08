# syshook

A tool to run scripts and functions in response to syscalls and other events on
a hooked program.

This tool is a WIP, but is intended to allow diagnostic scripts and fault injection
tests to be written.

Scripts are written in the [Janet](https://janet-lang.org/) programming language.

## Examples

hook the 'open-at' syscall

```
$ syshook \
  -e (sys-enter 257 (eprintf "open-at: path=%s" (arg-string 1))) \
  -- cat ./foobar.txt
open-at: path=.../lib/librt.so.1
open-at: path=.../lib/libc.so.6
...
open-at: path=./foobar.txt
foo!
```
