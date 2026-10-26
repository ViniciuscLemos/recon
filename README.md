# RECON

Point it at an unknown binary and it tries to work out what the program does, from the evidence inside the file.

Work in progress. The static analysis comes first, and what works today is reading the file, its imports and strings, comparing two versions of the same program, and finding the functions in the code and who calls whom.

## What works so far

```bash
pip install -e .
recon info program.exe      # format, what it can probably do, packing hints, sections, imports, exports
recon strings program.exe   # printable strings with their address
recon funcs program.exe     # functions found in the code, with what they call
recon func program.exe main # one function: who calls it, what it calls, imports, strings
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

Without reading a single instruction you can already tell the file writing went away and network code came in, with the server address and what gets sent. The next step is finding which functions changed, which needs the code itself (below).

`info` also warns when a program looks packed (UPX and similar section names, code with entropy above 7.2, code that is also writable). A packed program keeps its real code compressed until it runs, so its imports and strings say very little, and an empty result shouldn't be trusted.

## Functions and who calls whom

`recon funcs` disassembles the code with [Capstone](https://www.capstone-engine.org) (x86-64 only for now). It starts from what the file already gives away (entry point, exports, symbols and the x64 exception table, which lists where each function starts and ends) and then follows every direct call to find the rest. For each function it keeps the functions it calls, the imported APIs it calls and the data it points at, so a string like `"10.0.0.5"` gets tied to the function that uses it.

This is the part I like the most. Compiling login_v2 with `-s` throws away every function name, and this is what's left of the function that talks to the server:

```
$ recon func login_v2_stripped.exe 0x1400017f9
FUN_1400017f9 at 0x1400017f9..0x140001902, 55 instructions

called by (1)
  FUN_140001902

calls (1)
  FUN_140003360

imports (9)
  WSACleanup
  WSAStartup
  closesocket
  connect
  htons
  inet_pton
  send
  socket
  strlen

strings (2)
  '10.0.0.5'
  'POST /audit HTTP/1.1\r\nHost: %s\r\n\r\nuser=%s&ok=%d'
```

No names, but it's pretty clear what it does, and `FUN_140001902` (its caller) is the one that uses the `"Username:"` prompt, so that's `main`. On the build with symbols the same function shows up as `report_attempt`, called by `main`, which is how I checked it got it right.

MinGW calls imports through small `jmp [iat]` stubs and Linux through the PLT, so a call to one of those counts as a call to the import, and the stub isn't listed as a function of its own.

## Known limits

- Everything is static. A program that downloads or unpacks its code at runtime shows only its loader.
- Capabilities come from a small table of known functions. Anything called through `GetProcAddress`, or through syscalls directly, isn't seen yet.
- Strings are plain ASCII and UTF-16 runs of 4 or more visible characters. Encoded or built-at-runtime strings don't show up.
- A function ends where the exception table says, or at the next known start when there's no table (ELF). That works on compiler output, but hand-written or obfuscated code can fool it.
- Calls through a register (`call rax`, virtual methods, callbacks) are only counted, not followed.
- Only x86 and x86-64 have been tried, and the disassembly is x86-64 only. ARM files load, but nothing past the headers has been checked on them.

Testing it on Windows' own binaries (notepad, kernel32, ntdll, Edge) and on broken files turned up a few things that are handled now: MinGW names its longer sections `/4`, `/29`... and the real name (`.debug_info`) sits in a table at the end of the file, a DLL with no entry point used to show the image base as its entry, and a file cut short used to load quietly with nothing in it, which looks just like a program that does nothing.

## Tests

```bash
pip install -e .[dev]
pytest
```

The tests build the samples with whatever `gcc` is on the machine, so on Windows they check PE files and on Linux ELF files. CI runs both.

MIT license.
