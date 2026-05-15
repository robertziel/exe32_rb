# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # The 16 general-purpose registers plus RIP.
    #
    # Naming follows Intel encoding order: rax, rcx, rdx, rbx, rsp, rbp, rsi,
    # rdi, r8..r15. ModR/M encodes these by index 0..15 (high bit comes from
    # the REX.R/REX.B/REX.X extension).
    #
    # x86_64 sub-register write semantics, encoded here:
    #   - write to 64-bit:  whole register replaced.
    #   - write to 32-bit:  ZERO-extended to 64 bits (the surprising rule).
    #   - write to 16-bit:  upper 48 bits preserved.
    #   - write to  8-bit:  upper 56 bits preserved (low byte form).
    #   - write to AH/CH/DH/BH (legacy high byte, only without REX prefix):
    #     bits 8..15 replaced, others preserved.
    class Registers
      MASK64 = 0xFFFF_FFFF_FFFF_FFFF
      MASK32 = 0x0000_0000_FFFF_FFFF
      MASK16 = 0x0000_0000_0000_FFFF
      MASK8  = 0x0000_0000_0000_00FF

      NAMES_64 = %w[rax rcx rdx rbx rsp rbp rsi rdi
                    r8 r9 r10 r11 r12 r13 r14 r15].freeze
      NAMES_32 = %w[eax ecx edx ebx esp ebp esi edi
                    r8d r9d r10d r11d r12d r13d r14d r15d].freeze
      NAMES_16 = %w[ax cx dx bx sp bp si di
                    r8w r9w r10w r11w r12w r13w r14w r15w].freeze
      # Low byte form, used whenever a REX prefix is present
      NAMES_8L = %w[al cl dl bl spl bpl sil dil
                    r8b r9b r10b r11b r12b r13b r14b r15b].freeze
      # No-REX byte form: indices 0..3 are AL/CL/DL/BL (low byte),
      # indices 4..7 are AH/CH/DH/BH (high byte of RAX/RCX/RDX/RBX).
      NAMES_8H = %w[al cl dl bl ah ch dh bh].freeze

      RAX = 0
      RCX = 1
      RDX = 2
      RBX = 3
      RSP = 4
      RBP = 5
      RSI = 6
      RDI = 7
      R8  = 8
      R9  = 9

      attr_accessor :rip
      attr_reader   :gpr

      def initialize
        @gpr = Array.new(16, 0)
        @rip = 0
      end

      # --- whole-width accessors ----------------------------------------------

      def read64(idx); @gpr[idx]; end
      def read32(idx); @gpr[idx] & MASK32; end
      def read16(idx); @gpr[idx] & MASK16; end
      def read8l(idx); @gpr[idx] & MASK8; end
      def read8h(idx); (@gpr[idx] >> 8) & MASK8; end

      def write64(idx, value)
        @gpr[idx] = value & MASK64
      end

      def write32(idx, value)
        # 32-bit writes zero-extend to 64 bits
        @gpr[idx] = value & MASK32
      end

      def write16(idx, value)
        @gpr[idx] = (@gpr[idx] & ~MASK16) | (value & MASK16)
      end

      def write8l(idx, value)
        @gpr[idx] = (@gpr[idx] & ~MASK8) | (value & MASK8)
      end

      def write8h(idx, value)
        @gpr[idx] = (@gpr[idx] & ~(MASK8 << 8)) | ((value & MASK8) << 8)
      end

      # --- sized convenience --------------------------------------------------

      def read(size, idx, high_byte: false)
        case size
        when 8  then high_byte ? read8h(idx) : read8l(idx)
        when 16 then read16(idx)
        when 32 then read32(idx)
        when 64 then read64(idx)
        else raise Exe32Rb::ExecutionError, "bad register size: #{size}"
        end
      end

      def write(size, idx, value, high_byte: false)
        case size
        when 8  then high_byte ? write8h(idx, value) : write8l(idx, value)
        when 16 then write16(idx, value)
        when 32 then write32(idx, value)
        when 64 then write64(idx, value)
        else raise Exe32Rb::ExecutionError, "bad register size: #{size}"
        end
      end

      def name(size, idx, high_byte: false)
        case size
        when 8  then high_byte ? NAMES_8H.fetch(idx) : NAMES_8L.fetch(idx)
        when 16 then NAMES_16.fetch(idx)
        when 32 then NAMES_32.fetch(idx)
        when 64 then NAMES_64.fetch(idx)
        end
      end

      def to_s
        rows = (0...16).map do |i|
          format("%-3s = 0x%016X", NAMES_64[i], @gpr[i])
        end
        ([format("rip = 0x%016X", @rip)] + rows).join("\n")
      end
    end
  end
end
