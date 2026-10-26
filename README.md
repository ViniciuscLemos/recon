# RECON

Point it at an unknown binary and it tries to work out what the program does, from the evidence inside the file. It never runs the program.

![Call graph rebuilt from a binary with no function names](docs/call-graph.png)

That's a small login program compiled with `-s`, so every function name is gone. RECON still finds the functions, who calls whom, and which system APIs and strings each one uses. The "was" names are only there because I checked them against the build with symbols afterwards.

## Why I'm making this

A lot of "AI reverse engineering" demos throw the whole binary at a model and hope for the best. I wanted to build the boring part first: the actual analysis, done with real tools, that produces evidence you can check. The plan is for an AI agent to sit on top of that later and answer questions like "which function does the authentication?" by navigating the analysis, citing what it found.

It's also the excuse I needed to learn PE/ELF internals, x86-64 and disassembly properly.

## Try it

```bash
pip install -e .
recon info program.exe       # format, what it can probably do, packing hints, sections, imports, exports
recon strings program.exe    # printable strings with their address
recon funcs program.exe      # functions found in the code, with what they call
recon func program.exe main  # one function: who calls it, what it calls, imports, strings
recon diff old.exe new.exe   # what changed between two versions
```

Add `--json` before the command (`recon --json funcs program.exe`) to get JSON instead of text. Works on PE (Windows) and ELF (Linux) files, read with [LIEF](https://lief.re) and disassembled with [Capstone](https://www.capstone-engine.org).

`samples/` has the two login programs I use to test it. Version 2 stops writing a local log file and reports each login attempt to a server instead, and that's the change all the examples below are about.

## Taking apart a stripped binary

![recon func on the function that talks to the server](docs/func.png)

`recon funcs` starts from what the file already gives away (entry point, exports, symbols and the x64 exception table, which lists where each function starts and ends) and then follows every direct `call` until no new functions show up. For each one it keeps the functions it calls, the imported APIs it calls and the data it points at, so a string like `"10.0.0.5"` gets tied to the code that uses it.

So even with no names, `FUN_1400017f9` is obviously the one talking to the server, and its only caller is the function that prints `"Username:"`, which makes that one `main`.

The part that took me a while: MinGW never calls `connect` directly. It calls a tiny stub that only does `jmp [import table]`, and at first every stub showed up as a function of its own, with the network calls spread across them. Now a call to one of those stubs counts as a call to the import (Linux does the same thing with the PLT).

On a real program it holds up too. Windows' notepad.exe has 423 functions, found in about 2 seconds, and this is one of them:

```
$ recon func notepad.exe FUN_14000ca10
FUN_14000ca10 at 0x14000ca10..0x14000cb73, 85 instructions

called by (2)
  FUN_14000d078
  FUN_14000d54c

calls (2)
  FUN_1400019f0
  FUN_140023ae0

imports (4)
  CloseHandle
  CreateFileW
  IsTextUnicode
  ReadFile
```

Opens a file, reads it and checks whether the text is Unicode. Pretty sure that's part of opening a document.

## Comparing two versions

![recon diff between login v1 and v2](docs/diff.png)

`recon diff` compares imports, strings and what each version can probably do. Without reading a single instruction you can tell the file writing went away and network code came in, with the server address and what gets sent.

After that it lists the functions that changed:

```
+ func    report_attempt, 55 instructions
            + calls snprintf, WSACleanup, WSAStartup, closesocket, connect, htons, inet_pton, send, socket, strlen
            + uses '10.0.0.5', 'POST /audit HTTP/1.1\r\nHost: %s\r\n\r\nuser=%s&ok=%d'
+ func    snprintf, 30 instructions
            + calls __local_stdio_printf_options, __stdio_common_vsprintf
- func    log_attempt, 24 instructions
            - calls fprintf, fclose, fopen
            - uses 'denied', 'login attempt user=%s result=%s', 'login.log'
~ func    check_login, 16 -> 23 instructions
~ func    main, 39 instructions
            + calls report_attempt
            - calls log_attempt
```

That's exactly what I changed in the source: the log function was swapped for one that reports to the server, `main` calls the new one, and `check_login` got the lockout after three failures. `hash_password` didn't change, so it isn't listed.

To know which old function is which new one, it pairs them by name first, then by identical code (the same sequence of instructions, even at another address), and last by the imports and strings they share. That's why it works on stripped builds too: comparing the two `-s` versions gives the same five changes, just with `FUN_` names. The last step is a guess, though. A function that changed a lot and uses nothing distinctive shows up as one removed and one added.

## What a program can probably do

![recon info on login v2](docs/info.png)

"Can probably" comes from grouping the imports: `socket`/`connect`/`send` mean network, `fopen`/`WriteFile` mean writing files, `CreateProcess` means starting other programs, and so on. An import only says the program *can* call something, so each one is listed with the imports behind it. Some come from the compiler's startup code: every MinGW build imports `LoadLibraryA` and `GetProcAddress`, so "dynamic loading" shows up even in the samples. Now that functions are mapped, the next step is only counting imports that the program's own code calls.

`info` also warns when a program looks packed (UPX and similar section names, code with entropy above 7.2, code that is also writable). A packed program keeps its real code compressed until it runs, so its imports and strings say very little, and an empty result shouldn't be trusted.

## Where it's at

Done: loading PE/ELF, strings, imports and exports, capabilities, packing hints, finding functions with the call graph, and the version diff down to which functions changed.

Next, roughly in this order: control flow inside a function and cross-references (who uses this string or this global), 32-bit x86, then the AI layer that answers questions with evidence from all of this. Running samples in a sandbox to watch what they actually do is further out.

## Known limits

- Everything is static. A program that downloads or unpacks its code at runtime shows only its loader.
- Capabilities come from a small table of known functions. Anything called through `GetProcAddress`, or through syscalls directly, isn't seen yet.
- Strings are plain ASCII and UTF-16 runs of 4 or more visible characters. Encoded or built-at-runtime strings don't show up.
- A function ends where the exception table says, or at the next known start when there's no table (ELF). That works on compiler output, but hand-written or obfuscated code can fool it.
- Calls through a register (`call rax`, virtual methods, callbacks) are only counted, not followed.
- The disassembly is x86-64 only. ARM files load, but nothing past the headers has been checked on them.

Testing it on Windows' own binaries (notepad, kernel32, ntdll, Edge) and on broken files turned up a few things that are handled now: MinGW names its longer sections `/4`, `/29`... and the real name (`.debug_info`) sits in a table at the end of the file, a DLL with no entry point used to show the image base as its entry, and a file cut short used to load quietly with nothing in it, which looks just like a program that does nothing.

## How the code is split

`loader.py` turns what LIEF reads into one small model for both formats, so nothing after it cares whether it's PE or ELF. `strings.py`, `capabilities.py` and `packing.py` work on that model, `disasm.py` finds the functions and builds the call graph (NetworkX), `diff.py` and `funcdiff.py` compare two binaries, and `cli.py` is the `recon` command.

## Tests

```bash
pip install -e .[dev]
pytest
```

The tests build the samples with whatever `gcc` is on the machine, so on Windows they check PE files and on Linux ELF files. CI runs both.

MIT license.
