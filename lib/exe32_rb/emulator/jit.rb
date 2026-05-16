# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Tier-3 JIT: compile a basic block of consecutive guest instructions
    # into a single Ruby method that calls each instruction's executor
    # method handle inline. Eliminates the per-instruction overhead of the
    # step-loop branch / icache lookup / RIP write — for a hot loop of N
    # instructions, we go from N step-loop iterations to one.
    #
    # A "basic block" ends at the first instruction that can change
    # control flow non-trivially (branch, ret, halt, API call, etc).
    # Linear runs of arith/move/load/store get fused into one Ruby method.
    #
    # Cache is invalidated when memory writes touch the page of a cached
    # block (via Memory#write_callback). For programs whose .text doesn't
    # change at runtime — the common case — blocks are compiled once and
    # reused forever.
    class JIT
      # Mnemonics that terminate a basic block: the next instruction's
      # address depends on runtime state and we can't fuse past them.
      TERMINATORS = %i[
        jmp jmp_indirect jcc call call_indirect ret
        int int3 syscall hlt
        rep_movs rep_stos rep_lods rep_cmps rep_scas
      ].to_set

      Block = Struct.new(:start_rip, :instructions, :end_rip, :handle)

      def initialize(machine, max_block_length: 64)
        @machine = machine
        @blocks  = {}  # start_rip => Block
        @max     = max_block_length
        # Bind Memory write callback for invalidation if it's not already
        # bound (icache invalidation lived here in an earlier session).
        old_cb = machine.memory.write_callback
        machine.memory.write_callback = lambda do |addr, size|
          old_cb&.call(addr, size)
          invalidate_pages(addr, size)
        end
      end

      attr_reader :blocks

      # Execute one basic block. Returns the number of instructions
      # actually run (added to steps_executed in bulk by the caller).
      def run_block(rip)
        block = @blocks[rip] ||= compile(rip)
        block.handle.call
      end

      def in_cache?(rip); @blocks.key?(rip); end

      private

      # Compile by linear-scanning up to @max instructions. Stop at the
      # first terminator (inclusive — terminators are emitted; their effect
      # on rip is what ends the block).
      def compile(start_rip)
        instrs = []
        rip = start_rip
        @max.times do
          inst = @machine.decoder.decode(rip)
          inst.executor_handle ||= @machine.executor.method(:"op_#{inst.mnemonic}")
          instrs << inst
          rip = (rip + inst.length) & @machine.cpu.address_mask
          break if TERMINATORS.include?(inst.mnemonic)
          # Bail if the next address is no longer in .text (unmapped /
          # jumping into scratch); the interpreter handles it.
          break unless @machine.in_text?(rip)
        end
        handle = build_block_proc(instrs)
        Block.new(start_rip, instrs, rip, handle)
      end

      # Build a Proc that runs the block. The Proc captures the cpu,
      # executor, mask, and instruction array as locals (faster than
      # ivars in MRI). The body has one direct executor call per
      # instruction.
      #
      # 32-bit x86 has no EIP-relative addressing, so executor methods
      # (other than CALL/Jcc/RET which are terminators) don't read eip.
      # Update eip ONCE at the end of the block to its final value
      # instead of after each instruction. (The terminator overwrites
      # eip anyway via push/jmp/etc., so this final value is only
      # actually visible if the block runs to its non-terminator end.)
      def build_block_proc(instrs)
        cpu       = @machine.cpu
        executor  = @machine.executor
        # Ruby's lexer warns "assigned but unused" for `cpu`, `executor`,
        # `instrs` because the lambda body lives in an eval string and
        # static analysis can't see it. Silence with a noop reference.
        _ = [cpu, executor, instrs]
        addr_mask = cpu.address_mask
        last_idx = instrs.size - 1
        terminator = TERMINATORS.include?(instrs.last.mnemonic)
        # Bind each instruction object as an outer local so the lambda
        # captures it directly — no per-call array indexing.
        instr_vars = (0...instrs.size).map { |i| "i#{i}" }
        binding_lines = instr_vars.each_with_index.map { |v, i|
          "#{v} = instrs[#{i}]"
        }
        # Body: just executor calls, no rip updates per step (32-bit has
        # no EIP-relative addressing; rip is set in bulk at block end /
        # terminator runs).
        body = []
        offset = 0
        instrs.each_with_index do |inst, idx|
          if idx == last_idx && terminator
            body << "cpu.rip = (cpu.rip + #{offset + inst.length}) & #{addr_mask}"
            body << "executor.op_#{inst.mnemonic}(#{instr_vars[idx]})"
          else
            body << "executor.op_#{inst.mnemonic}(#{instr_vars[idx]})"
            offset += inst.length
          end
        end
        unless terminator
          body.unshift "cpu.rip = (cpu.rip + #{offset}) & #{addr_mask}"
        end
        n = instrs.size
        source = <<~RUBY
          #{binding_lines.join("\n")}
          lambda do
            #{body.join("\n  ")}
            #{n}
          end
        RUBY
        eval(source, binding, "(jit @ 0x#{instrs.first.address.to_s(16)})", 1)
      end

      def invalidate_pages(addr, size)
        return if @blocks.empty?
        # Fast path: 99.9% of guest writes target stack/heap/scratch, NOT
        # executable .text. Skip the per-block scan entirely if the write
        # address isn't in .text. (Self-modifying code is rare and would
        # need a real invalidator anyway.)
        return unless @machine.in_text?(addr) || @machine.in_text?(addr + size - 1)

        page_lo = addr & ~0xFFF
        page_hi = (addr + size - 1) | 0xFFF
        @blocks.delete_if do |_start, b|
          b.start_rip <= page_hi && b.end_rip >= page_lo
        end
      end
    end
  end
end
