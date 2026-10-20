# RECON

Point it at an unknown binary and it tries to work out what the program does, from the evidence inside the file.

Work in progress. The static analysis comes first, and the part that works today is the cheap one: reading the file, its imports and strings, and comparing two versions of the same program.

## What works so far

```bash
pip install -e .
recon info program.exe      # format, what it can probably do, sections, imports
recon strings program.exe   # printable strings with their address
recon diff old.exe new.exe  # what changed between two versions
```

Add `--json` before the command (`recon --json info program.exe`) to get JSON instead of text.

It reads PE (Windows) and ELF (Linux) files with [LIEF](https://lief.re) and never runs them.

"What it can probably do" comes from grouping the imported functions: `socket`/`connect`/`send` mean network, `fopen`/`WriteFile` mean writing files, `CreateProcess` means starting other programs, and so on. An import only says the program *can* call something, so each one is listed with the imports behind it. Some come from the compiler's own startup code: every MinGW build imports `LoadLibraryA` and `GetProcAddress`, so "dynamic loading" shows up even in the samples. Telling those apart needs the code analysis that comes next.

`samples/` has two small login programs I wrote to have something to take apart. Version 2 stops writing a local log file and reports each login to a server instead. Compiled with MinGW on my PC, this is what `recon diff` says about them:

```
+ can     network
- can     file write
+ import  WSACleanup
+ import  WSAStartup
+ import  __stdio_common_vsprintf
+ import  closesocket
+ import  connect
+ import  htons
+ import  inet_pton
+ import  send
+ import  socket
- import  fclose
- import  fopen
+ string  '10.0.0.5'
+ string  'POST /audit HTTP/1.1\r\nHost: %s\r\n\r\nuser=%s&ok=%d'
- string  'denied'
- string  'login attempt user=%s result=%s'
- string  'login.log'
```

Without reading a single instruction you can already tell the file writing went away and network code came in, with the server address and what gets sent. The next step is finding which functions changed, which needs the code itself.

## Tests

```bash
pip install -e .[dev]
pytest
```

The tests build the samples with whatever `gcc` is on the machine, so on Windows they check PE files and on Linux ELF files. CI runs both.

MIT license.
