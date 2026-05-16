# exe32_rb

Pure-Ruby emulator for 32-bit Windows PE executables, built as a
**learning tool for understanding how x86 binaries actually run**.
Loads a PE32 / i386 `.exe`, maps its sections into a virtual address
space, interprets x86 instructions in 32-bit mode, and routes imported
Windows API calls to Ruby handlers via the `__stdcall` / `__cdecl`
conventions.

The headline feature for learning is the `debug` REPL — step instruction
by instruction through any PE32 binary, watch registers and flags
change, set breakpoints, inspect memory and the stack. See the
**[Learn x86 by stepping through it](#learn-x86-by-stepping-through-it)**
section below for a hands-on walkthrough.

The bundled `kernel32` handler set covers ~100 Win32 functions across
`kernel32` / `user32` / `advapi32` / `oleaut32` / `comctl32` with sensible
defaults, plus real host-backed `CreateFileW` / `ReadFile` / `WriteFile` /
`CloseHandle` (so the guest's file I/O actually lands on disk).

## Quick start

```sh
$ ruby tools/build_hello.rb            # writes examples/hello.exe
$ ./exe/exe32_rb dump   examples/hello.exe   # parse + print headers
$ ./exe/exe32_rb disasm examples/hello.exe -n 20
$ ./exe/exe32_rb run    examples/hello.exe   # -> Hello, world!
$ ./exe/exe32_rb debug  examples/hello.exe   # interactive step-debugger
```

CLI commands:

| Command | What it does |
| --- | --- |
| `dump <file.exe>` | Print PE headers, sections, and imports |
| `disasm <file.exe> [-n N]` | Disassemble N instructions from the entry point |
| `run <file.exe>` | Emulate the binary |
| `debug <file.exe>` | Drop into an interactive step-debugger REPL |
| `strings <file.exe>` | List every UTF-16 string in the binary's RT_STRING table |
| `hello <out.exe>` | Write a fresh minimal hello-world PE32 |
| `version` | Print version |

`run` options:

| Option | Effect |
| --- | --- |
| `--trace` | Echo every instruction + API call to stderr |
| `--stub-missing` | Install permissive stubs (correct arg counts) for every API in the signatures table; warn once per truly-unknown import |
| `--call-stub=ADDR[=RETVAL]` | Redirect `call [ADDR]` to a stub returning RETVAL (default 0). Repeatable. |
| `--patch=ADDR=HEX` | Overwrite guest memory at ADDR with HEX bytes after load (repeatable). |
| `--lenient` | Unmapped reads return 0; writes are dropped. Lets buggy code stumble forward. |
| `--max-steps N` | Cap the step count (defaults to 10M) |

## Learn x86 by stepping through it

The `debug` command opens an interactive REPL that lets you single-step
any PE32 binary, watching exactly how the CPU evolves. Try it on the
bundled factorial sample — a recursive function that exercises the
classic `push ebp / mov ebp,esp / ...` stack-frame pattern:

```sh
$ ruby -Ilib -rexe32_rb -e 'Exe32Rb::Samples::Factorial.write("examples/factorial.exe")'
$ ./exe/exe32_rb debug examples/factorial.exe
exe32_rb debugger — loaded factorial.exe
  entry  0x00401022
  rsp    0x700FFEFC
  1 imports bound across 1 DLLs
  type `help` for commands

(exe32) d 4
-> 0x00401022  6a 05                     push 0x5
   0x00401024  e8 d7 ff ff ff            call rip-41
   0x00401029  83 c4 04                  add esp, 0x4
   0x0040102C  50                        push eax

(exe32) s                  ; execute push 5
-> 0x00401024  e8 d7 ff ff ff            call rip-41

(exe32) stack              ; see the 5 on top of the stack
  [esp+ 0]  0x700FFEF8 = 0x00000005 <- esp
  ...

(exe32) s                  ; step into factorial(5)
-> 0x00401000  55                        push ebp

(exe32) s                  ; push ebp
(exe32) s                  ; mov ebp, esp
(exe32) regs               ; new frame: ebp == esp
  eax = 0x00000000    esi = 0x00000000
  ebx = 0x00000000    edi = 0x00000000
  ecx = 0x00000000    ebp = 0x700FFEF0
  edx = 0x00000000    esp = 0x700FFEF0

(exe32) c                  ; let it finish
── halted, exit_code=120
```

The exit code is 120 = 5!.

### Debugger commands

```
execution:                 inspection:
  s, step                    r, regs        registers + flags
  n, next  (step over CALL)  d, disasm [N]  N instructions from eip
  c, continue                x ADDR [N]     N bytes of memory
                             stack [N]      top N dwords from esp
breakpoints:                 imports        list IAT imports
  b   ADDR                   strings        dump RT_STRING resources
  bd  ADDR
  bl                         h, help        this help
                             q, quit        exit
```

### Things to try at the REPL

* `b 0x401029` then `c` — break after the recursive call returns and
  inspect `eax` to see each partial result (5, 20, 60, 120 as the
  recursion unwinds).
* `disasm 30` from the entry point — read the prologue / epilogue
  patterns and the recursive call's relative offset.
* `strings examples/akimbo-or-any.exe` — dump the binary's UI text
  without running a single instruction.
* `imports` — see exactly which Win32 functions the binary depends on,
  with the synthetic thunk addresses the dispatcher has bound.

## Host-backed file I/O

The bundled `Exe32Rb::Samples::HelloFile` fixture demonstrates real
Win32-to-host integration:

```ruby
require "exe32_rb"
require "tmpdir"

Dir.mktmpdir do |dir|
  exe = File.join(dir, "demo.exe")
  Exe32Rb::Samples::HelloFile.write(exe)
  Dir.chdir(dir) do
    Exe32Rb::Machine.from_path(exe).configure.run
  end
  File.read(File.join(dir, "exe_rb_demo.txt")) # => "Hello from exe_rb!\n"
end
```

The guest calls `CreateFileW` → `WriteFile` → `CloseHandle`; the
emulator's handlers open a real Ruby `File` object via a synthetic
handle table.

## Architecture

```
PE::Loader  ->  PE::Image  ->  Emulator::Machine
                                    |
                  +-----------------+----------------------+
                  |                 |                      |
            Emulator::Memory  Emulator::CPU          Api::Dispatcher
                                  |                        |
                          Decoder + Executor       Api::Conventions
                                                  (Stdcall32, Cdecl32)
                                                            |
                                                      Api::Kernel32
                                                      Api::Signatures
                                                  (100+ Win32 APIs)
```

* `PE::Loader` parses both PE32 (i386) and PE32+ (x86_64). `Machine`
  refuses to set up unless the image is i386, so a PE32+ binary loads
  cleanly for `dump` but `run`/`disasm` reject it.
* `Emulator::Decoder` is the same mode-aware x86 decoder that handled
  both architectures previously; `Machine` instantiates it with
  `mode: 32`. The 32-bit specifics:
  REX bytes are real INC/DEC r32 opcodes, `mod=00 rm=101` is an
  absolute `disp32` (not RIP-relative), and stack defaults are 32-bit.
* `Emulator::CPU` exposes `mode`, `address_mask`, `fs_base`,
  `push_native`/`pop_native`, and a host-IO handle table
  (`register_handle` / `lookup_handle` / `close_handle`) plus
  `read_wstring` / `read_cstring` helpers used by the kernel32 handlers.
* `Api::Dispatcher` patches the guest IAT with synthetic thunk
  addresses. When the CPU lands on one, the dispatcher reads N args via
  the configured `Conventions` adapter, runs the Ruby handler, writes
  the return register, and cleans up. `install_call_stub(at_address)`
  hooks a non-IAT call-through-pointer.
* `Api::Signatures` maps `(dll, name) -> [arg_count, default_return]`
  for ~100 Win32 functions. `--stub-missing` uses this so unhandled
  calls don't drift the `__stdcall` stack.

## Running real-world binaries (Delphi installers etc.)

For binaries that are more than a hello-world, the runtime offers
several escalating tools:

```sh
# Permissive defaults: stub unknown APIs, neutralize a single
# in-binary function pointer (a memmgr / vtable slot you've spotted)
./exe/exe32_rb run --stub-missing \
                   --call-stub=0x412740 \
                   some-installer.exe
```

```sh
# Full pipeline for a Delphi-built binary:
./exe/exe32_rb run --stub-missing \
                   --delphi-memmgr=0x41273C \      # replace Delphi's TMemoryManager
                   --winfs \                       # sandbox C:\ paths in /tmp
                   --watch=0x12345 \               # log writes touching ADDR
                   some-installer.exe
```

What each flag does:

* **`--stub-missing`** — installs no-op handlers (with correct arg counts)
  for every Win32 function in `Api::Signatures`. Keeps the guest stack
  honest for unhandled `__stdcall` calls.
* **`--call-stub=ADDR[=N]`** — patch the 4 bytes at ADDR with the address
  of a synthetic thunk; calls through that pointer land in a Ruby stub
  returning N. Use to neutralize a single misbehaving function pointer.
* **`--patch=ADDR=HEX`** — overwrite guest memory at load time. Useful
  for short-circuiting a known-bad function with a `C3` (RET) byte.
* **`--watch=ADDR`** — log every write touching ADDR with the current
  EIP and full register dump. Finds the instruction that corrupted state.
* **`--delphi-memmgr=ADDR`** — replace Delphi's 6-slot TMemoryManagerEx
  record (at ADDR) with Ruby `GetMem`/`FreeMem`/`ReallocMem`/`AllocMem`
  handlers. The biggest single-flag leap for any Delphi 2009+ binary —
  without this, FastMM-format header reads scattered across the binary
  will fault.
* **`--winfs[=DIR]`** — translate all `C:\…` paths to host paths under
  a sandbox directory. The binary thinks it has a real Windows fs.
* **`--lenient`** — unmapped reads return 0, writes are dropped. Lets
  buggy guests stumble forward. Off by default (can mask real bugs).

The emulator's own self-healing:

* **`MemoryError` → SEH** — every access violation synthesizes
  `EXCEPTION_ACCESS_VIOLATION (0xC0000005)` and dispatches through the
  guest's `FS:[0]` exception chain. If a handler runs to completion,
  the binary's own try/finally/except logic gets to run.
* **`RaiseException` → SEH** — same path; the guest's Delphi `raise`
  reaches its own handlers instead of halting.
* **`RtlUnwind`** — walks the SEH chain to the target frame.

## What's intentionally missing

* **No CRT, no DLL loader.** Imports resolve to Ruby handlers; the
  binary needs to call `ExitProcess` (or you handle the entry-point's
  `RET`) to halt cleanly. `LoadLibrary`/`GetProcAddress` return fake
  handles.
* **Permission bits are tracked, not enforced.** Writes to read-only
  pages succeed silently.
* **No real FPU / SSE / AVX.** x87 instructions decode as length-correct
  no-ops; XMM/YMM operations don't decode yet.
* **No COM.** `CoCreateInstance` is a stub; DirectX / OLE binaries
  won't get useful interfaces.
* **No real registry.** Reads return plausible defaults (LCID 0x0409,
  empty strings, success codes).
* **No GUI.** Win32 window creation, message pump, GDI rendering are
  all stubbed. `MessageBoxA/W` is rendered as an ASCII dialog on stderr.

## Running tests

```sh
rake test     # decoder/executor unit tests + hello-world + hello-file
```

## License

MIT.
