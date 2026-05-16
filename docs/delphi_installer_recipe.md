# Running a Delphi-built InnoSetup installer through exe32_rb

This is the recipe for getting a Delphi 2009/2010-era setup `.exe`
(typical InnoSetup format) through the emulator far enough to exercise
its install logic, with all the runtime fixes the binary tends to need.

## Invocation

```sh
./exe/exe32_rb run --stub-missing \
                   --call-stub=<MEMMGR_FREEMEM_PTR_ADDR> \
                   --delphi-memmgr=<MEMMGR_RECORD_ADDR> \
                   --winfs \
                   path/to/setup.exe
```

The two binary-specific addresses you need:

1. **MemoryManager record address** — Delphi embeds a 6-slot
   `TMemoryManagerEx` record in `.data`. To find it:
   ```sh
   ./exe/exe32_rb dump setup.exe  # note the .data section's VA range
   ```
   Then look in `.data` (with a hex viewer) for a run of 6 consecutive
   little-endian DWORDs whose values fall in the `.text` section's
   range. That's the record. Its first slot is `GetMem`.

2. **FreeMem pointer (optional but useful)** — same as slot 1 of the
   record above (memmgr_addr + 4). `--call-stub=<addr>` writes a
   no-op thunk into that pointer so any inlined FreeMem call sites
   that reach that pointer become harmless.

## What each flag does

* **`--stub-missing`** — auto-installs handlers (with the right arg
  counts) for ~100 Win32 functions the binary will probably call.
  Keeps the `__stdcall` stack honest.
* **`--call-stub=ADDR[=N]`** — patches a 4-byte function-pointer slot
  at ADDR to point at a Ruby stub returning N (default 0).
* **`--delphi-memmgr=ADDR`** — the heavy hitter. Replaces all 6 slots
  of the Delphi memory manager with Ruby handlers backed by our scratch
  allocator. Without this, the binary's own GetMem/FreeMem (built into
  the `.text`) will trip on FastMM-style header invariants almost
  immediately.
* **`--winfs[=DIR]`** — sandboxes `C:\...` paths into a host directory
  (default `/tmp/exe32_rb_root`). Host-absolute (`/foo`) paths pass
  through unchanged.

## What you should see

```
[call-stub] 0x<addr> will return 0
[memmgr] replaced 6 slots at 0x<addr>
[winfs] sandbox root: /tmp/exe32_rb_root
[FindFirstFileW] ""
[CreateFileW] <host-absolute path> -> <host-absolute path>
```

The binary opens its own .exe (read for self-extraction), reads chunks
via ReadFile, and begins integrity-checking them via CRC-32. At that
point it's CPU-bound in the interpreter; with only ~30M instructions
per second in pure-Ruby we don't finish the validation of a multi-MB
payload in any reasonable time.

## Common walls (and what to do)

| Symptom | Cause | Workaround |
| --- | --- | --- |
| `Delphi exception 0x0EEDFADE` early on | Resource-string table uninitialized — the binary tried to show an error message and the message resource lookup failed | Look at the recent `LoadStringW` lookups (auto-printed in MessageBox annotations) — the missing string usually tells you what state the binary actually wanted |
| `read of unmapped page at 0x...` after ~1.4M instructions | Delphi's own GetMem/FreeMem layout mismatch | Use `--delphi-memmgr=ADDR` |
| String passed to CreateFileW is garbled (every 4th byte off by 1-2) | FPU FILD/FISTP precision loss | Already fixed in `lib/exe32_rb/emulator/executor.rb` (FPU stores Integer values losslessly) |
| `CreateDirectoryW("is-")` (no random suffix) | Delphi runtime path-builder couldn't construct the suffix string | Often indicates a deeper RTL state issue; check what the binary's `IntToHex` / `Format` produces with `--watch` and `--break` |
| Binary appears to hang forever | Tight CPU loop (often CRC validation or compression) | Expected — interpreter is ~1000x slower than native. A JIT would be needed to make real-world installers finish in practical time. |

## Tools for figuring out walls

* `exe32_rb dump <file>` — sections + imports
* `exe32_rb strings <file>` — every UTF-16 string in RT_STRING
* `exe32_rb disasm <file> -n N` — disassemble entry point
* `exe32_rb debug <file>` — interactive single-step REPL
* `--trace` — log every executed instruction + API call
* `--watch=ADDR` — log every write touching ADDR, with register dump
* `--break=ADDR` — log register state every time EIP hits ADDR
* `--patch=ADDR=HEX` — overwrite guest memory at load time

The watch + break + patch combo is a working substitute for a
breakpoint-style debugger when you're trying to localize a wall.
