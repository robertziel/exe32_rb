# frozen_string_literal: true

module Exe32Rb
  module Api
    # Replace a Delphi binary's TMemoryManagerEx record with Ruby handlers.
    #
    # Delphi 2009+ binaries embed a 6-slot TMemoryManagerEx record in their
    # .data section:
    #
    #   +0   GetMem(Size: NativeInt): Pointer            ; register
    #   +4   FreeMem(P: Pointer): Integer                 ; register
    #   +8   ReallocMem(P: Pointer; Size: NativeInt): Pointer  ; register
    #   +12  AllocMem(Size: NativeInt): Pointer           ; register
    #   +16  RegisterExpectedMemoryLeak(P: Pointer): Bool ; register
    #   +20  UnregisterExpectedMemoryLeak(P: Pointer): Bool ; register
    #
    # Each function uses Delphi's "register" calling convention (first 3
    # args in EAX/EDX/ECX, return in EAX). The runtime calls them via the
    # record AND via direct CALL rel32 instructions inlined by the compiler.
    # We patch both: write thunk addresses into the record AND overwrite
    # the first 5 bytes of each original function with `JMP rel32` to the
    # matching thunk.
    #
    # Our allocator uses Machine#scratch_alloc with a 16-byte FastMM-style
    # header: [ret-4] = rounded size with low 4 bits clear. Free is a no-op
    # (we don't reclaim — short-lived programs only). HeapSize / OwnsBlock
    # patterns aren't covered; binaries that walk the heap or check
    # ownership won't be helped by this.
    module DelphiMemMgr
      RECORD_SIZE = 24
      ALIGN       = 16

      # Install the replacement. memmgr_addr is the address of the first
      # function pointer slot (GetMem).
      def self.install(machine, memmgr_addr)
        conv = Conventions::DelphiRegister.new
        dispatcher = machine.dispatcher

        # Read original function addresses so we can patch them too.
        originals = (0...6).map { |i| machine.memory.read_u32(memmgr_addr + i * 4) }
        names = %w[GetMem FreeMem ReallocMem AllocMem
                   RegisterExpectedMemoryLeak UnregisterExpectedMemoryLeak]

        # Build handlers.
        get_mem = lambda do |mach, args|
          size = args[0] & 0xFFFF_FFFF
          allocate_block(mach, size, zero: false)
        end

        free_mem = lambda do |_mach, _args|
          0 # success
        end

        realloc_mem = lambda do |mach, args|
          old_p = args[0] & 0xFFFF_FFFF
          new_size = args[1] & 0xFFFF_FFFF
          new_p = allocate_block(mach, new_size, zero: false)
          if old_p != 0 && new_p != 0
            old_size = (mach.memory.read_u32(old_p - 4) & 0xFFFF_FFF0)
            copy = [old_size, new_size].min
            mach.memory.write(new_p, mach.memory.read(old_p, copy)) if copy > 0
          end
          new_p
        end

        alloc_mem = lambda do |mach, args|
          allocate_block(mach, args[0] & 0xFFFF_FFFF, zero: true)
        end

        no_op_bool = lambda do |_mach, _args|
          1 # success
        end

        impls = [get_mem, free_mem, realloc_mem, alloc_mem, no_op_bool, no_op_bool]
        arg_counts = [1, 1, 2, 1, 1, 1]

        # Register thunks + patch the record.
        thunks = (0...6).map do |i|
          dispatcher.install_thunk("delphi.#{names[i]}",
                                    args: arg_counts[i], convention: conv,
                                    &impls[i])
        end

        thunks.each_with_index do |thunk, i|
          machine.memory.write_u32(memmgr_addr + i * 4, thunk)
        end

        # Patch each original function with JMP rel32 to the thunk so direct
        # (non-pointer) callers also get intercepted.
        originals.each_with_index do |orig, i|
          next if orig == 0

          rel = (thunks[i] - orig - 5) & 0xFFFF_FFFF
          machine.memory.write(orig, [0xE9].pack("C") + [rel].pack("V"))
        end

        warn format("[memmgr] replaced 6 slots at 0x%08X (GetMem was 0x%08X, FreeMem 0x%08X)",
                     memmgr_addr, originals[0], originals[1])
        {originals: originals, thunks: thunks}
      end

      # Allocate with a FastMM-style 16-byte header before the returned
      # pointer. [ret-4] = rounded size; low 4 bits zero (= "regular block").
      # 8 bytes of trailing slack so [ret + size - 4] is always mapped.
      def self.allocate_block(machine, size, zero:)
        return 0 if size == 0

        rounded = (size + ALIGN - 1) & ~(ALIGN - 1)
        base = machine.scratch_alloc(rounded + 24, zero: true)
        return 0 if base == 0

        ret = base + 16
        machine.memory.write_u32(ret - 4, rounded)
        # When zero is false, scratch is already zeroed by scratch_alloc;
        # this lambda exists for API symmetry.
        ret
      end
    end
  end
end
