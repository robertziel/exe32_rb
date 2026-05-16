# Running Akimbo through exe32_rb — current best state and what's left

This doc captures the state I pushed the Akimbo InnoSetup installer
(`setup_akimbo_kung-fu_hero_2.0_(74845).exe`) to over a long deep-dive
session, and what's known about the remaining walls.

## Current best invocation

```sh
./exe/exe32_rb run --stub-missing \
                   --call-stub=0x412740 \
                   --delphi-memmgr=0x41273C \
                   --winfs \
                   'examples/Akimbo.Kungfu.Hero.v2.0/setup_akimbo_kung-fu_hero_2.0_(74845).exe'
```

What it does:

1. Loads the PE32 image, maps sections, sets up TIB.
2. Replaces the Delphi `TMemoryManagerEx` record at `0x41273C` with
   Ruby `GetMem`/`FreeMem`/`ReallocMem`/`AllocMem` handlers that use
   our scratch with FastMM-shaped headers.
3. Installs default stubs (with correct arg counts) for ~100 Win32
   functions.
4. Sets up a sandboxed `C:\` filesystem under `/tmp/exe32_rb_root/`.
5. Runs the binary's startup → CRT init → install loop.
6. Reaches `CreateDirectoryW("is-")` — actually creates a real
   directory at `<sandbox>/C/Temp/is-`.
7. Binary raises `Delphi exception 0x0EEDFADE` and exits cleanly via
   `ExitProcess(1)` — the same controlled-error path it would take on
   a real Windows machine missing localization or specific RTL state.

## What was learned during deep-dive

### The fundamental wall

The binary's path-build code at function `0x40E62F` (which contains the
loop at `0x40E7F0`) builds the temp dir name by:

```
ConcatN(out, 4, [rbp-4], "is-", [rbp-28], [rbp-12])
```

The 5-char base-32 suffix is built by a sub-function at `0x40E724`:

```
loop 5 times:
  edx = esi & 0x1F
  ch  = lookup_table[edx*2]
  call _LStrFromChar(ch)  → produces 1-char UnicodeString
  call concat(output, [single_char_str], 1)
  esi >>= 5
```

With our setup, `0x40E724` is called once with `eax=0x00101109` (a
non-zero seed), runs without exception, and returns. But the
`[rbp-28]` output slot in the caller stays empty by the time the outer
`ConcatN` runs, so the final string is just `"is-"` (the `[rbp-4]` and
`[rbp-12]` slots are also empty).

The root cause is that Delphi's UnicodeString operations
(`_LStrFromChar`, `_LStrAsg`, the concat builders) read and write
per-allocation header fields:

- `[ptr-12]`: codepage word + element-size word
- `[ptr-8]`: refcount
- `[ptr-4]`: length (in chars)

Our `GetMem` returns blocks with the right FastMM size field at
`[ptr-4]`, but Delphi's UnicodeString init writes its own header
fields starting 12 bytes BEFORE the user pointer. The interaction
between FastMM headers and UnicodeString headers depends on the
binary's exact Delphi version's `PStrRec` layout and the precise byte
offsets compiled-in.

### What didn't work

| Approach | Result | Why |
| --- | --- | --- |
| Patch validator at `0x401D89` with NOPs | Same fault one instruction later | Next load also reads bad address |
| Replace `[0x412740]` (FreeMem function pointer) | Same fault from direct call site | Function called both via pointer AND direct CALL rel32 |
| `--patch=0x401C7C=C3` (entry-RET) | Same fault elsewhere | Many call sites to similar functions |
| `--patch=0x402030=9090909090` (call site NOP) | Different fault: `cmp [rax-8], 0x1` | Distributed FastMM-header reads across many functions |
| `--call-stub` on the format function entry | `CreateDirectoryW("")` (worse) | Bypassing the function leaves stack/state mismatched |
| Synthesize UnicodeString header in Ruby | Caller's reads still see wrong values | Header field offsets are binary-specific |

### What would work (with substantial work)

1. **Implement a bit-compatible FastMM2/FastMM4 allocator** for the
   exact Delphi version this binary was built with. Requires
   reverse-engineering the binary's `MemoryManager` record's
   initialization code to determine which FastMM version is embedded
   and replicating its block layout precisely.

2. **Patch each call site that reads UnicodeString headers** with a
   JMP to a Ruby thunk that does the read with our layout knowledge.
   Hundreds of call sites; binary-specific.

3. **Implement a real Delphi RTL** for string/object operations as
   Ruby intercepts. Means modeling `LStrFromChar`, `LStrAsg`,
   `LStrCat`, `UStrAsg`, `UStrCat`, ref-counting, copy-on-write
   semantics. Multi-week project per Delphi version.

4. **Run the binary's full Delphi CRT init code** end-to-end. That
   requires more Win32 surface (SEH already done, but also full COM,
   working DLL loader, the `kernel32` thread/mutex/event surface, etc.).

None of these are tractable in single-session iteration; each is a
multi-day project.

## Useful tools left behind for future sessions

The session built infrastructure that's general-purpose, not
Akimbo-specific:

- **`--watch=ADDR`** — log writes to a guest address with register dump
- **`--break=ADDR`** — log register state every time EIP hits ADDR
- **`--patch=ADDR=HEX`** — overwrite guest memory at load time
- **`--call-stub=ADDR[=N]`** — redirect a function-pointer call to a stub
- **`--delphi-memmgr=ADDR`** — replace 6-slot TMemoryManagerEx record
- **`--winfs[=DIR]`** — sandbox `C:\…` paths under a host directory
- **SEH dispatch** — every access violation routes through `FS:[0]` chain
- **Real `GetLastError`** — actual state across handlers

## What CAN run today

Anything that:
- Doesn't depend on Delphi-internal allocator metadata invariants
- Uses standard Win32 calls (file I/O, registry stubs, env vars)
- Stays within the SEH-supported exception model
- Doesn't need COM, DirectX, working DLL loading, or a real GUI

The bundled hello-world and factorial samples; simple console programs
built with non-Delphi toolchains.
