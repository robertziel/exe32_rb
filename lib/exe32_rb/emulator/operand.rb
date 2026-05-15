# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Operand value types. Plain data; no behavior beyond presentation.
    module Operand
      # size is in bits: 8, 16, 32, 64.

      # Register operand. `idx` is 0..15 (the underlying full-width register).
      # When `high_byte` is true (only for AH/CH/DH/BH), idx is still 0..3 but
      # the operand selects bits 8..15 of that register.
      Reg = Struct.new(:size, :idx, :high_byte, keyword_init: true) do
        def to_s
          case size
          when 8  then high_byte ? Registers::NAMES_8H[idx + 4] : Registers::NAMES_8L[idx]
          when 16 then Registers::NAMES_16[idx]
          when 32 then Registers::NAMES_32[idx]
          when 64 then Registers::NAMES_64[idx]
          end
        end
      end

      # Memory operand. base/index are full-width register indices or nil.
      # scale is 1/2/4/8. disp is a signed integer.
      # If rip_relative is true, base/index are nil and disp is added to the
      # RIP value AT the end of the instruction.
      # seg, when :fs or :gs, adds the corresponding CPU segment base before
      # the effective-address read or write (for TIB / TEB access).
      Mem = Struct.new(:size, :base, :index, :scale, :disp, :rip_relative, :seg, keyword_init: true) do
        def to_s
          inside = if rip_relative
                     format("rip%+d", disp)
                   else
                     str = +""
                     str << Registers::NAMES_64[base] if base
                     if index
                       str << "+" unless str.empty?
                       str << format("%s*%d", Registers::NAMES_64[index], scale)
                     end
                     if disp != 0 || str.empty?
                       str << format("%+d", disp) unless str.empty?
                       str = disp.to_s if str.empty?
                     end
                     str
                   end
          "#{size_keyword} ptr [#{inside}]"
        end

        def size_keyword
          case size
          when 8 then "byte"
          when 16 then "word"
          when 32 then "dword"
          when 64 then "qword"
          else "?"
          end
        end
      end

      # Immediate operand.
      Imm = Struct.new(:size, :value, :signed, keyword_init: true) do
        def to_s
          format("0x%X", value)
        end
      end

      # PC-relative operand (used for branch targets prior to resolution).
      Rel = Struct.new(:size, :offset, keyword_init: true) do
        def to_s
          format("rip%+d", offset)
        end
      end
    end
  end
end
