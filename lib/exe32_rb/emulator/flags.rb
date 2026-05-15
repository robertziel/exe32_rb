# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # RFLAGS — only the arithmetic/control flags we actually use.
    #
    # Layout helpers below compute CF/ZF/SF/OF/PF/AF after an operation given
    # operand size and operands. Callers do the actual arithmetic; we just
    # record the side effects.
    class Flags
      attr_accessor :cf, :pf, :af, :zf, :sf, :df, :of, :if_

      def initialize
        @cf  = false
        @pf  = false
        @af  = false
        @zf  = false
        @sf  = false
        @df  = false
        @of  = false
        @if_ = true
      end

      def sign_mask(size); 1 << (size - 1); end
      def value_mask(size); (1 << size) - 1; end

      # Compute and store ZF, SF, PF given a result of `size` bits.
      def set_logic_flags(result, size)
        mask = value_mask(size)
        masked = result & mask
        @zf = masked == 0
        @sf = (masked & sign_mask(size)) != 0
        @pf = even_parity?(masked & 0xFF)
        nil
      end

      # ADD-style: result = a + b (truncated). Sets CF, OF, AF, plus logic flags.
      def set_add_flags(a, b, result, size)
        mask = value_mask(size)
        sm   = sign_mask(size)
        truncated = result & mask
        @cf = result > mask
        @of = ((~(a ^ b) & (a ^ truncated)) & sm) != 0
        @af = (((a ^ b ^ truncated) & 0x10) != 0)
        set_logic_flags(truncated, size)
      end

      # SUB-style: result = a - b (may be negative; we store low `size` bits).
      def set_sub_flags(a, b, result, size)
        mask = value_mask(size)
        sm   = sign_mask(size)
        truncated = result & mask
        @cf = (a & mask) < (b & mask)
        @of = (((a ^ b) & (a ^ truncated)) & sm) != 0
        @af = (((a ^ b ^ truncated) & 0x10) != 0)
        set_logic_flags(truncated, size)
      end

      # AND / OR / XOR clear CF and OF, leave AF undefined (we leave it as-is),
      # and set ZF/SF/PF from the result.
      def set_logic_op_flags(result, size)
        @cf = false
        @of = false
        set_logic_flags(result, size)
      end

      # Pack as the standard RFLAGS layout.
      def to_i
        v = 0
        v |= 0x0001 if @cf
        v |= 0x0004 if @pf
        v |= 0x0010 if @af
        v |= 0x0040 if @zf
        v |= 0x0080 if @sf
        v |= 0x0200 if @if_
        v |= 0x0400 if @df
        v |= 0x0800 if @of
        v |= 0x0002 # reserved bit, always 1
        v
      end

      def to_s
        [@cf ? "CF" : "cf", @pf ? "PF" : "pf", @af ? "AF" : "af",
         @zf ? "ZF" : "zf", @sf ? "SF" : "sf", @df ? "DF" : "df",
         @of ? "OF" : "of"].join(" ")
      end

      private

      EVEN_PARITY_LUT = (0..255).map { |b|
        ones = 0
        x = b
        while x > 0
          ones += x & 1
          x >>= 1
        end
        ones.even?
      }.freeze

      def even_parity?(byte)
        EVEN_PARITY_LUT[byte & 0xFF]
      end
    end
  end
end
