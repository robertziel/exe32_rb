# exe32_rb

Pure-Ruby emulator for 32-bit Windows PE executables. Loads a PE32 / i386
`.exe`, maps its sections into a virtual address space, interprets x86
instructions in 32-bit mode, and routes imported Windows API calls to
Ruby handlers via the `__stdcall` / `__cdecl` conventions.

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
```

CLI commands:

| Command | What it does |
| --- | --- |
| `dump <file.exe>` | Print PE headers, sections, and imports |
| `disasm <file.exe> [-n N]` | Disassemble N instructions from the entry point |
| `run <file.exe>` | Emulate the binary |
| `hello <out.exe>` | Write a fresh minimal hello-world PE32 |
| `version` | Print version |

`run` options:

| Option | Effect |
| --- | --- |
| `--trace` | Echo every instruction + API call to stderr |
| `--stub-missing` | Install permissive stubs (correct arg counts) for every API in the signatures table; warn once per truly-unknown import |
| `--call-stub=ADDR` | Redirect `call [ADDR]` to a return-1 thunk. Use to neutralize an in-binary memory-manager / vtable pointer that doesn't match our model. Repeatable. |
| `--max-steps N` | Cap the step count (defaults to 10M) |

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

## What's intentionally missing

* **No CRT, no DLL loader.** Imports resolve to Ruby handlers; the
  binary needs to call `ExitProcess` (or you handle the entry-point's
  `RET`) to halt cleanly.
* **Permission bits are tracked, not enforced.** Writes to read-only
  pages succeed silently.
* **No FPU / SSE / AVX state.** x87 instructions (D8..DF) and FWAIT
  decode as length-correct no-ops; XMM/YMM operations don't decode yet.
* **No SEH unwind** beyond `FS:[0]` returning `0xFFFFFFFF` and a TLS
  array of zero slots.
* **No real registry or GUI.** Stubs return plausible values but don't
  model the underlying state.
* **No real allocator.** `HeapAlloc` is a bump allocator inside a 16 MiB
  scratch region; deallocation is a no-op. Binaries with built-in
  memory managers (e.g., Delphi/FastMM) will eventually trip on heap
  metadata expectations — use `--call-stub=ADDR` to neutralize the
  in-binary free routine when that happens.

## Running tests

```sh
rake test     # decoder/executor unit tests + hello-world + hello-file
```

## License

MIT.
