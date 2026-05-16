# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Minimal x87 FPU model: 8-deep float stack with the standard
    # top-of-stack pointer, status word (C0/C1/C2/C3 condition codes,
    # TOP field), and control word.
    #
    # We use Ruby's native Float (IEEE 754 double, 64 bits) for register
    # contents — fidelity loss vs. real 80-bit extended precision but
    # sufficient for typical 32-bit Win32 / Delphi binaries that don't
    # rely on the extra precision.
    #
    # The FPU "stack" is indexed by `top`: ST(i) refers to register
    # registers[(top + i) & 7]. FLD pushes (decrements top, writes new
    # ST(0)); FSTP pops (writes the operand, increments top).
    class FPU
      attr_accessor :top, :control, :status, :tags
      attr_reader   :registers

      def initialize
        @registers = Array.new(8, 0.0)
        @top       = 0
        @control   = 0x037F # default Intel value
        @status    = 0x0000
        @tags      = 0xFFFF # all empty
      end

      def push(value)
        @top = (@top - 1) & 0x7
        @registers[@top] = value
      end

      def pop
        value = @registers[@top]
        @top = (@top + 1) & 0x7
        value
      end

      def st(i)
        @registers[(@top + i) & 0x7]
      end

      def set_st(i, value)
        @registers[(@top + i) & 0x7] = value
      end

      def empty?
        # We don't strictly track per-register validity; the tag word is
        # initialized to "all empty" but we don't decrement it on every
        # push. Real binaries seldom inspect the tag word; if they do,
        # this approximation can break and we'll need to track properly.
        false
      end

      # FCOM/FCOMI set condition codes based on the comparison.
      # For FCOM, C3=ZF, C2=PF, C0=CF (mapped from the float comparison).
      # For FCOMI, the result lands in CPU EFLAGS (handled by executor).
      def set_compare_flags(left, right)
        if left.nan? || right.nan?
          # unordered → C3=C2=C0=1
          @status = (@status & ~0x4500) | 0x4500
        elsif left > right
          @status = (@status & ~0x4500)              # C3=C2=C0=0
        elsif left < right
          @status = (@status & ~0x4500) | 0x0100     # C0=1
        else # equal
          @status = (@status & ~0x4500) | 0x4000     # C3=1
        end
      end

      # 16-bit status word with TOP field at bits 11..13.
      def status_word
        (@status & ~0x3800) | ((@top & 0x7) << 11)
      end
    end
  end
end
