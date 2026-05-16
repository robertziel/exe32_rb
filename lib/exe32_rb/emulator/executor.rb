# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Executes one decoded Instruction against the CPU and Memory.
    #
    # RIP is expected to already have been advanced past the instruction by
    # the caller (Machine#step) before invoking execute. That keeps
    # RIP-relative effective-address computation correct (it uses the address
    # of the NEXT instruction) and CALL/Jcc branch math straightforward.
    #
    # Coverage is the union of the decoder's coverage, with a handful of
    # rarely-used opcodes left as NotImplementedError stubs that you can fill
    # in when a real binary needs them.
    class Executor
      MASK64 = 0xFFFF_FFFF_FFFF_FFFF

      class HaltSignal < StandardError
        attr_reader :exit_code

        def initialize(exit_code = 0)
          super("machine halted")
          @exit_code = exit_code
        end
      end

      def initialize(cpu, memory)
        @cpu    = cpu
        @memory = memory
      end

      def execute(instr)
        method_name = :"op_#{instr.mnemonic}"
        unless respond_to?(method_name, true)
          raise Exe32Rb::ExecutionError, "no executor for mnemonic :#{instr.mnemonic} at 0x#{instr.address.to_s(16)}"
        end

        send(method_name, instr)
      end

      # ----------------------------------------------------------------
      # Data movement
      # ----------------------------------------------------------------

      def op_mov(instr)
        dst, src = instr.operands
        write_op(dst, read_op(src, dst.size))
      end

      def op_lea(instr)
        dst, src = instr.operands
        ea = effective_address(src)
        # LEA truncates the effective address to the destination operand size.
        write_op(dst, ea & mask(dst.size))
      end

      def op_movzx(instr)
        dst, src = instr.operands
        write_op(dst, read_op(src, src.size) & mask(dst.size))
      end

      def op_movsx(instr)
        dst, src = instr.operands
        write_op(dst, sign_extend(read_op(src, src.size), src.size, dst.size))
      end

      def op_movsxd(instr)
        op_movsx(instr)
      end

      def op_setcc(instr)
        op = instr.operands[0]
        write_op(op, condition_true?(instr.meta[:cc]) ? 1 : 0)
      end

      def op_push(instr)
        op = instr.operands[0]
        size = op.size == 16 ? 16 : @cpu.native_size
        value = read_op(op, size)
        case size
        when 64 then @cpu.push64(@memory, value)
        when 32 then @cpu.push32(@memory, value)
        when 16
          @cpu.rsp = (@cpu.rsp - 2) & @cpu.address_mask
          @memory.write_u16(@cpu.rsp, value)
        end
      end

      def op_pop(instr)
        op = instr.operands[0]
        size = op.size == 16 ? 16 : @cpu.native_size
        value = case size
                when 64 then @cpu.pop64(@memory)
                when 32 then @cpu.pop32(@memory)
                when 16
                  v = @memory.read_u16(@cpu.rsp)
                  @cpu.rsp = (@cpu.rsp + 2) & @cpu.address_mask
                  v
                end
        write_op(op, value)
      end

      # ----------------------------------------------------------------
      # Binary arithmetic and logic
      # ----------------------------------------------------------------

      def op_add(instr)
        a, b, size, dst = binary_inputs(instr)
        r = a + b
        @cpu.flags.set_add_flags(a, b, r, size)
        write_op(dst, r & mask(size))
      end

      def op_or(instr)
        a, b, size, dst = binary_inputs(instr)
        r = (a | b) & mask(size)
        @cpu.flags.set_logic_op_flags(r, size)
        write_op(dst, r)
      end

      def op_adc(instr)
        a, b, size, dst = binary_inputs(instr)
        c = @cpu.flags.cf ? 1 : 0
        r = a + b + c
        @cpu.flags.set_add_flags(a, b + c, r, size)
        write_op(dst, r & mask(size))
      end

      def op_sbb(instr)
        a, b, size, dst = binary_inputs(instr)
        c = @cpu.flags.cf ? 1 : 0
        r = a - b - c
        @cpu.flags.set_sub_flags(a, b + c, r, size)
        write_op(dst, r & mask(size))
      end

      def op_and(instr)
        a, b, size, dst = binary_inputs(instr)
        r = (a & b) & mask(size)
        @cpu.flags.set_logic_op_flags(r, size)
        write_op(dst, r)
      end

      def op_sub(instr)
        a, b, size, dst = binary_inputs(instr)
        r = a - b
        @cpu.flags.set_sub_flags(a, b, r, size)
        write_op(dst, r & mask(size))
      end

      def op_xor(instr)
        a, b, size, dst = binary_inputs(instr)
        r = (a ^ b) & mask(size)
        @cpu.flags.set_logic_op_flags(r, size)
        write_op(dst, r)
      end

      def op_cmp(instr)
        a, b, size, _ = binary_inputs(instr)
        r = a - b
        @cpu.flags.set_sub_flags(a, b, r, size)
      end

      def op_test(instr)
        a, b, size, _ = binary_inputs(instr)
        r = (a & b) & mask(size)
        @cpu.flags.set_logic_op_flags(r, size)
      end

      # ----------------------------------------------------------------
      # Unary
      # ----------------------------------------------------------------

      def op_inc(instr)
        op = instr.operands[0]
        size = op.size
        a = read_op(op, size)
        r = (a + 1) & mask(size)
        old_cf = @cpu.flags.cf
        @cpu.flags.set_add_flags(a, 1, a + 1, size)
        @cpu.flags.cf = old_cf
        write_op(op, r)
      end

      def op_dec(instr)
        op = instr.operands[0]
        size = op.size
        a = read_op(op, size)
        r = (a - 1) & mask(size)
        old_cf = @cpu.flags.cf
        @cpu.flags.set_sub_flags(a, 1, a - 1, size)
        @cpu.flags.cf = old_cf
        write_op(op, r)
      end

      def op_neg(instr)
        op = instr.operands[0]
        size = op.size
        a = read_op(op, size)
        r = (-a) & mask(size)
        @cpu.flags.set_sub_flags(0, a, -a, size)
        @cpu.flags.cf = (a != 0)
        write_op(op, r)
      end

      def op_not(instr)
        op = instr.operands[0]
        size = op.size
        a = read_op(op, size)
        write_op(op, (~a) & mask(size))
      end

      # ----------------------------------------------------------------
      # Shifts (count masked to 5 or 6 bits per Intel)
      # ----------------------------------------------------------------

      def op_shl(instr)
        shift_op(instr) do |a, count, size|
          result = (a << count) & mask(size)
          cf = ((a >> (size - count)) & 1) != 0
          [result, cf]
        end
      end
      alias_method :op_sal, :op_shl

      def op_shr(instr)
        shift_op(instr) do |a, count, size|
          result = (a & mask(size)) >> count
          cf = ((a >> (count - 1)) & 1) != 0
          [result, cf]
        end
      end

      def op_sar(instr)
        shift_op(instr) do |a, count, size|
          signed = signed_of(a, size)
          result = (signed >> count) & mask(size)
          cf = ((a >> (count - 1)) & 1) != 0
          [result, cf]
        end
      end

      def shift_op(instr)
        dst, count_op = instr.operands
        size = dst.size
        count_raw = read_op(count_op, 8)
        count = count_raw & (size == 64 ? 0x3F : 0x1F)
        return if count == 0

        a = read_op(dst, size)
        result, cf = yield(a, count, size)
        @cpu.flags.cf = cf
        if count == 1
          msb = (result & sign_mask(size)) != 0
          @cpu.flags.of = (instr.mnemonic == :shl || instr.mnemonic == :sal) ? (msb != cf) : false
        end
        @cpu.flags.set_logic_flags(result, size)
        write_op(dst, result)
      end

      # ----------------------------------------------------------------
      # Control flow
      # ----------------------------------------------------------------

      def op_call(instr)
        rel = instr.operands[0]
        target = (@cpu.rip + rel.offset) & @cpu.address_mask
        @cpu.push_native(@memory, @cpu.rip)
        @cpu.rip = target
      end

      def op_call_indirect(instr)
        target = read_op(instr.operands[0])
        @cpu.push_native(@memory, @cpu.rip)
        @cpu.rip = target
      end

      def op_ret(instr)
        @cpu.rip = @cpu.pop_native(@memory)
        if (extra = instr.operands.first)
          @cpu.rsp = (@cpu.rsp + extra.value) & @cpu.address_mask
        end
      end

      def op_jmp(instr)
        op = instr.operands[0]
        @cpu.rip = (@cpu.rip + op.offset) & @cpu.address_mask
      end

      def op_jmp_indirect(instr)
        @cpu.rip = read_op(instr.operands[0])
      end

      def op_jcc(instr)
        if condition_true?(instr.meta[:cc])
          @cpu.rip = (@cpu.rip + instr.operands[0].offset) & @cpu.address_mask
        end
      end

      # ----------------------------------------------------------------
      # Miscellany
      # ----------------------------------------------------------------

      def op_nop(_); end
      def op_fpu_nop(_); end # x87 instructions silently skipped (no FPU model)

      # AH <-> flags transfers (used by Borland/Delphi floating-point compare
      # paths via FCOM + FSTSW + SAHF).
      def op_sahf(_)
        ah = @cpu.registers.read8h(Registers::RAX)
        @cpu.flags.cf = (ah & 0x01) != 0
        @cpu.flags.pf = (ah & 0x04) != 0
        @cpu.flags.af = (ah & 0x10) != 0
        @cpu.flags.zf = (ah & 0x40) != 0
        @cpu.flags.sf = (ah & 0x80) != 0
      end

      def op_lahf(_)
        v = 0x02 # bit 1 reserved, always 1
        v |= 0x01 if @cpu.flags.cf
        v |= 0x04 if @cpu.flags.pf
        v |= 0x10 if @cpu.flags.af
        v |= 0x40 if @cpu.flags.zf
        v |= 0x80 if @cpu.flags.sf
        @cpu.registers.write8h(Registers::RAX, v)
      end

      def op_xchg(instr)
        a_op, b_op = instr.operands
        size = a_op.size
        a = read_op(a_op, size)
        b = read_op(b_op, size)
        write_op(a_op, b)
        write_op(b_op, a)
      end

      # ----------------------------------------------------------------
      # String ops (MOVS, STOS, LODS, CMPS, SCAS)
      # ----------------------------------------------------------------

      PACK_FMT = {8 => "C", 16 => "v", 32 => "V", 64 => "Q<"}.freeze

      def op_movs(instr)
        size  = instr.meta[:op_size]
        bytes = size / 8
        step  = (@cpu.flags.df ? -bytes : bytes)
        count = string_count(instr)
        rsi   = @cpu.registers.read(@cpu.mode, Registers::RSI)
        rdi   = @cpu.registers.read(@cpu.mode, Registers::RDI)
        count.times do
          @memory.write(rdi, @memory.read(rsi, bytes))
          rsi = (rsi + step) & @cpu.address_mask
          rdi = (rdi + step) & @cpu.address_mask
        end
        @cpu.registers.write(@cpu.mode, Registers::RSI, rsi)
        @cpu.registers.write(@cpu.mode, Registers::RDI, rdi)
        @cpu.registers.write(@cpu.mode, Registers::RCX, 0) if instr.meta[:rep]
      end

      def op_stos(instr)
        size  = instr.meta[:op_size]
        bytes = size / 8
        step  = (@cpu.flags.df ? -bytes : bytes)
        count = string_count(instr)
        value = @cpu.registers.read(size, Registers::RAX)
        rdi   = @cpu.registers.read(@cpu.mode, Registers::RDI)
        packed = [value].pack(PACK_FMT[size])
        count.times do
          @memory.write(rdi, packed)
          rdi = (rdi + step) & @cpu.address_mask
        end
        @cpu.registers.write(@cpu.mode, Registers::RDI, rdi)
        @cpu.registers.write(@cpu.mode, Registers::RCX, 0) if instr.meta[:rep]
      end

      def op_lods(instr)
        size  = instr.meta[:op_size]
        bytes = size / 8
        step  = (@cpu.flags.df ? -bytes : bytes)
        count = string_count(instr)
        rsi   = @cpu.registers.read(@cpu.mode, Registers::RSI)
        value = 0
        count.times do
          value = read_size(rsi, size)
          rsi = (rsi + step) & @cpu.address_mask
        end
        @cpu.registers.write(size, Registers::RAX, value)
        @cpu.registers.write(@cpu.mode, Registers::RSI, rsi)
        @cpu.registers.write(@cpu.mode, Registers::RCX, 0) if instr.meta[:rep]
      end

      def op_cmps(instr)
        # Single iteration; if REP is present we run the loop with ZF semantics.
        size  = instr.meta[:op_size]
        bytes = size / 8
        step  = (@cpu.flags.df ? -bytes : bytes)
        rep   = instr.meta[:rep]
        loop_body = lambda do
          rsi = @cpu.registers.read(@cpu.mode, Registers::RSI)
          rdi = @cpu.registers.read(@cpu.mode, Registers::RDI)
          a = read_size(rsi, size)
          b = read_size(rdi, size)
          r = a - b
          @cpu.flags.set_sub_flags(a, b, r, size)
          @cpu.registers.write(@cpu.mode, Registers::RSI, (rsi + step) & @cpu.address_mask)
          @cpu.registers.write(@cpu.mode, Registers::RDI, (rdi + step) & @cpu.address_mask)
        end
        if rep
          count = @cpu.registers.read(@cpu.mode, Registers::RCX)
          stop_on = rep == :rep ? true : false # REPE: stop when ZF=0; REPNE: stop when ZF=1
          count.times do |i|
            loop_body.call
            @cpu.registers.write(@cpu.mode, Registers::RCX, count - i - 1)
            break if @cpu.flags.zf != stop_on
          end
        else
          loop_body.call
        end
      end

      def op_scas(instr)
        size  = instr.meta[:op_size]
        bytes = size / 8
        step  = (@cpu.flags.df ? -bytes : bytes)
        rep   = instr.meta[:rep]
        acc   = @cpu.registers.read(size, Registers::RAX)
        loop_body = lambda do
          rdi = @cpu.registers.read(@cpu.mode, Registers::RDI)
          v   = read_size(rdi, size)
          r   = acc - v
          @cpu.flags.set_sub_flags(acc, v, r, size)
          @cpu.registers.write(@cpu.mode, Registers::RDI, (rdi + step) & @cpu.address_mask)
        end
        if rep
          count = @cpu.registers.read(@cpu.mode, Registers::RCX)
          stop_on = rep == :rep ? true : false
          count.times do |i|
            loop_body.call
            @cpu.registers.write(@cpu.mode, Registers::RCX, count - i - 1)
            break if @cpu.flags.zf != stop_on
          end
        else
          loop_body.call
        end
      end

      def string_count(instr)
        instr.meta[:rep] ? @cpu.registers.read(@cpu.mode, Registers::RCX) : 1
      end

      def read_size(addr, size)
        case size
        when 8  then @memory.read_u8(addr)
        when 16 then @memory.read_u16(addr)
        when 32 then @memory.read_u32(addr)
        when 64 then @memory.read_u64(addr)
        end
      end
      def op_clc(_); @cpu.flags.cf = false; end
      def op_stc(_); @cpu.flags.cf = true;  end
      def op_cld(_); @cpu.flags.df = false; end
      def op_std(_); @cpu.flags.df = true;  end

      def op_int3(instr)
        raise Exe32Rb::ExecutionError, "INT3 hit at 0x#{instr.address.to_s(16)}"
      end

      def op_hlt(_)
        raise HaltSignal.new(0)
      end

      def op_int(instr)
        raise Exe32Rb::ExecutionError, "INT 0x#{instr.operands[0].value.to_s(16)} not supported"
      end

      def op_syscall(_)
        raise Exe32Rb::ExecutionError, "SYSCALL not supported (Windows uses IAT, not syscall)"
      end

      def op_cqo(_)
        rax = @cpu.registers.read64(Registers::RAX)
        @cpu.registers.write64(Registers::RDX, (rax & sign_mask(64)) != 0 ? MASK64 : 0)
      end

      def op_cdq(_)
        eax = @cpu.registers.read32(Registers::RAX)
        @cpu.registers.write32(Registers::RDX, (eax & sign_mask(32)) != 0 ? mask(32) : 0)
      end

      def op_cwd(_)
        ax = @cpu.registers.read16(Registers::RAX)
        @cpu.registers.write16(Registers::RDX, (ax & sign_mask(16)) != 0 ? mask(16) : 0)
      end

      def op_cdqe(_)
        eax = @cpu.registers.read32(Registers::RAX)
        @cpu.registers.write64(Registers::RAX, sign_extend(eax, 32, 64))
      end

      def op_cwde(_)
        ax = @cpu.registers.read16(Registers::RAX)
        @cpu.registers.write32(Registers::RAX, sign_extend(ax, 16, 32))
      end

      def op_cbw(_)
        al = @cpu.registers.read8l(Registers::RAX)
        @cpu.registers.write16(Registers::RAX, sign_extend(al, 8, 16))
      end

      def op_rdtsc(_)
        # Return a monotonically-increasing fake TSC. Sufficient for code that
        # only cares about ordering, not real cycle counts.
        tsc = @rdtsc_count ||= 0
        @rdtsc_count += 1
        @cpu.registers.write32(Registers::RAX, tsc & 0xFFFF_FFFF)
        @cpu.registers.write32(Registers::RDX, (tsc >> 32) & 0xFFFF_FFFF)
      end

      def op_div(instr)
        op = instr.operands[0]
        size = op.size
        divisor = read_op(op, size)
        raise Exe32Rb::ExecutionError, "divide by zero" if divisor == 0

        case size
        when 8
          dividend = @cpu.registers.read16(Registers::RAX)
          q, r = dividend.divmod(divisor)
          raise Exe32Rb::ExecutionError, "DIV overflow" if q > 0xFF
          @cpu.registers.write8l(Registers::RAX, q)
          @cpu.registers.write8h(Registers::RAX, r)
        when 16
          dividend = (@cpu.registers.read16(Registers::RDX) << 16) | @cpu.registers.read16(Registers::RAX)
          q, r = dividend.divmod(divisor)
          raise Exe32Rb::ExecutionError, "DIV overflow" if q > 0xFFFF
          @cpu.registers.write16(Registers::RAX, q)
          @cpu.registers.write16(Registers::RDX, r)
        when 32
          dividend = (@cpu.registers.read32(Registers::RDX) << 32) | @cpu.registers.read32(Registers::RAX)
          q, r = dividend.divmod(divisor)
          raise Exe32Rb::ExecutionError, "DIV overflow" if q > 0xFFFF_FFFF
          @cpu.registers.write32(Registers::RAX, q)
          @cpu.registers.write32(Registers::RDX, r)
        when 64
          dividend = (@cpu.registers.read64(Registers::RDX) << 64) | @cpu.registers.read64(Registers::RAX)
          q, r = dividend.divmod(divisor)
          raise Exe32Rb::ExecutionError, "DIV overflow" if q > 0xFFFF_FFFF_FFFF_FFFF
          @cpu.registers.write64(Registers::RAX, q)
          @cpu.registers.write64(Registers::RDX, r)
        end
      end

      def op_idiv(instr)
        op = instr.operands[0]
        size = op.size
        divisor = signed_of(read_op(op, size), size)
        raise Exe32Rb::ExecutionError, "divide by zero" if divisor == 0

        # Reconstruct the signed dividend from RDX:RAX (or smaller pair).
        case size
        when 8
          dividend = signed_of(@cpu.registers.read16(Registers::RAX), 16)
        when 16
          combined = (@cpu.registers.read16(Registers::RDX) << 16) | @cpu.registers.read16(Registers::RAX)
          dividend = signed_of(combined, 32)
        when 32
          combined = (@cpu.registers.read32(Registers::RDX) << 32) | @cpu.registers.read32(Registers::RAX)
          dividend = signed_of(combined, 64)
        when 64
          combined = (@cpu.registers.read64(Registers::RDX) << 64) | @cpu.registers.read64(Registers::RAX)
          dividend = signed_of(combined, 128)
        end

        # x86 truncates toward zero; Ruby Integer#divmod floors. Adjust.
        q = (dividend.fdiv(divisor)).truncate
        r = dividend - q * divisor

        case size
        when 8
          @cpu.registers.write8l(Registers::RAX, q & 0xFF)
          @cpu.registers.write8h(Registers::RAX, r & 0xFF)
        when 16
          @cpu.registers.write16(Registers::RAX, q & 0xFFFF)
          @cpu.registers.write16(Registers::RDX, r & 0xFFFF)
        when 32
          @cpu.registers.write32(Registers::RAX, q & 0xFFFF_FFFF)
          @cpu.registers.write32(Registers::RDX, r & 0xFFFF_FFFF)
        when 64
          @cpu.registers.write64(Registers::RAX, q & 0xFFFF_FFFF_FFFF_FFFF)
          @cpu.registers.write64(Registers::RDX, r & 0xFFFF_FFFF_FFFF_FFFF)
        end
      end

      def op_mul(instr)
        op = instr.operands[0]
        size = op.size
        a = @cpu.registers.read(size, Registers::RAX)
        b = read_op(op, size)
        product = a * b
        low = product & mask(size)
        high = (product >> size) & mask(size)
        case size
        when 8
          @cpu.registers.write16(Registers::RAX, (high << 8) | low)
        else
          @cpu.registers.write(size, Registers::RAX, low)
          @cpu.registers.write(size, Registers::RDX, high)
        end
        @cpu.flags.cf = high != 0
        @cpu.flags.of = high != 0
      end

      def op_imul(instr)
        case instr.operands.size
        when 1
          op = instr.operands[0]
          size = op.size
          a = signed_of(@cpu.registers.read(size, Registers::RAX), size)
          b = signed_of(read_op(op, size), size)
          product = a * b
          low = product & mask(size)
          high = (product >> size) & mask(size)
          if size == 8
            @cpu.registers.write16(Registers::RAX, (high << 8) | low)
          else
            @cpu.registers.write(size, Registers::RAX, low)
            @cpu.registers.write(size, Registers::RDX, high) unless size == 8
          end
          overflow = (product != sign_extend(low, size, size * 2))
          @cpu.flags.cf = overflow
          @cpu.flags.of = overflow
        when 2
          dst, src = instr.operands
          size = dst.size
          a = signed_of(read_op(dst, size), size)
          b = signed_of(read_op(src, size), size)
          product = a * b
          low = product & mask(size)
          overflow = (product != sign_extend(low, size, size * 2))
          @cpu.flags.cf = overflow
          @cpu.flags.of = overflow
          write_op(dst, low)
        when 3
          # 3-operand form: dst = src1 * src2 (where src2 is an immediate).
          dst, src1, src2 = instr.operands
          size = dst.size
          a = signed_of(read_op(src1, size), size)
          b_raw = read_op(src2, size)
          b = signed_of(b_raw, src2.size)
          product = a * b
          low = product & mask(size)
          overflow = (product != sign_extend(low, size, size * 2))
          @cpu.flags.cf = overflow
          @cpu.flags.of = overflow
          write_op(dst, low)
        else
          raise Exe32Rb::ExecutionError, "IMUL with #{instr.operands.size} operands not implemented"
        end
      end

      # ----------------------------------------------------------------
      # Operand access
      # ----------------------------------------------------------------

      private

      def binary_inputs(instr)
        dst, src = instr.operands
        size = dst.size
        a = read_op(dst, size)
        b = read_op(src, size)
        [a, b, size, dst]
      end

      def read_op(op, target_size = nil)
        case op
        when Operand::Reg
          op.high_byte ? @cpu.registers.read8h(op.idx) : @cpu.registers.read(op.size, op.idx)
        when Operand::Mem
          read_mem(op)
        when Operand::Imm
          target = target_size || op.size
          op.value & mask(target)
        when Operand::Rel
          (@cpu.rip + op.offset) & @cpu.address_mask
        else
          raise Exe32Rb::ExecutionError, "cannot read operand #{op.inspect}"
        end
      end

      def write_op(op, value)
        case op
        when Operand::Reg
          if op.high_byte
            @cpu.registers.write8h(op.idx, value)
          else
            @cpu.registers.write(op.size, op.idx, value)
          end
        when Operand::Mem
          write_mem(op, value)
        else
          raise Exe32Rb::ExecutionError, "cannot write operand #{op.inspect}"
        end
      end

      def read_mem(op)
        addr = effective_address(op)
        case op.size
        when 8  then @memory.read_u8(addr)
        when 16 then @memory.read_u16(addr)
        when 32 then @memory.read_u32(addr)
        when 64 then @memory.read_u64(addr)
        end
      end

      def write_mem(op, value)
        addr = effective_address(op)
        case op.size
        when 8  then @memory.write_u8(addr, value)
        when 16 then @memory.write_u16(addr, value)
        when 32 then @memory.write_u32(addr, value)
        when 64 then @memory.write_u64(addr, value)
        end
      end

      def effective_address(op)
        ea = if op.rip_relative
               (@cpu.rip + op.disp) & @cpu.address_mask
             else
               e = 0
               e += @cpu.registers.read(@cpu.mode, op.base)             if op.base
               e += @cpu.registers.read(@cpu.mode, op.index) * op.scale if op.index
               (e + op.disp) & @cpu.address_mask
             end
        case op.seg
        when :fs then (ea + @cpu.fs_base) & @cpu.address_mask
        when :gs then (ea + @cpu.gs_base) & @cpu.address_mask
        else ea
        end
      end

      def condition_true?(cc)
        f = @cpu.flags
        case cc
        when :o   then f.of
        when :no  then !f.of
        when :b   then f.cf
        when :ae  then !f.cf
        when :e   then f.zf
        when :ne  then !f.zf
        when :be  then f.cf || f.zf
        when :a   then !f.cf && !f.zf
        when :s   then f.sf
        when :ns  then !f.sf
        when :p   then f.pf
        when :np  then !f.pf
        when :l   then f.sf != f.of
        when :ge  then f.sf == f.of
        when :le  then f.zf || (f.sf != f.of)
        when :g   then !f.zf && (f.sf == f.of)
        else
          raise Exe32Rb::ExecutionError, "unknown condition code: #{cc}"
        end
      end

      def mask(size); (1 << size) - 1; end
      def sign_mask(size); 1 << (size - 1); end

      def signed_of(value, size)
        sm = sign_mask(size)
        (value & sm) != 0 ? value - (1 << size) : value
      end

      def sign_extend(value, from_size, to_size)
        sm = sign_mask(from_size)
        if (value & sm) != 0
          # extend the sign bits
          ((value | ~mask(from_size)) & mask(to_size))
        else
          value & mask(to_size)
        end
      end
    end
  end
end
