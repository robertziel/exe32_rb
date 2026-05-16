# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # CPU state: registers + flags. The execution loop lives on Machine; CPU
    # is the container the loop operates on. Keeping state here means the
    # Decoder and Executor stay easy to test in isolation.
    class CPU
      attr_reader :registers, :flags, :mode, :fpu, :xmm

      attr_accessor :fs_base, :gs_base

      def initialize(mode: 64)
        @registers = Registers.new
        @flags     = Flags.new
        @mode      = mode
        @fs_base   = 0
        @gs_base   = 0
        @fpu       = FPU.new
        @xmm       = XMM.new(count: mode == 64 ? 16 : 8)
      end

      def address_mask
        @mode == 64 ? 0xFFFF_FFFF_FFFF_FFFF : 0xFFFF_FFFF
      end

      def native_size
        @mode
      end

      def rip;          @registers.rip; end
      def rip=(value);  @registers.rip = value & address_mask; end
      def rsp;          @registers.read64(Registers::RSP); end
      def rsp=(value);  @registers.write64(Registers::RSP, value & address_mask); end

      def push64(memory, value)
        new_rsp = (rsp - 8) & address_mask
        self.rsp = new_rsp
        memory.write_u64(new_rsp, value)
      end

      def pop64(memory)
        value = memory.read_u64(rsp)
        self.rsp = (rsp + 8) & address_mask
        value
      end

      def push32(memory, value)
        new_rsp = (rsp - 4) & address_mask
        self.rsp = new_rsp
        memory.write_u32(new_rsp, value & 0xFFFF_FFFF)
      end

      def pop32(memory)
        value = memory.read_u32(rsp)
        self.rsp = (rsp + 4) & address_mask
        value
      end

      def push_native(memory, value)
        @mode == 64 ? push64(memory, value) : push32(memory, value)
      end

      def pop_native(memory)
        @mode == 64 ? pop64(memory) : pop32(memory)
      end

      def inspect
        format("#<CPU mode=%d rip=0x%016X rsp=0x%016X flags=%s>", @mode, rip, rsp, flags)
      end
    end
  end
end
