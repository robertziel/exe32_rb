# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # XMM register file for SSE/SSE2/SSE3/SSSE3.
    #
    # 8 registers in 32-bit mode (xmm0..xmm7), 16 in 64-bit (xmm0..xmm15).
    # Each register is 128 bits (16 bytes). We store them as Ruby Strings
    # for direct slice/pack convenience.
    class XMM
      attr_reader :registers

      def initialize(count: 8)
        @registers = Array.new(count) { "\x00".b * 16 }
      end

      def read(idx)
        @registers[idx].dup
      end

      def write(idx, bytes)
        bytes = bytes.b
        raise ArgumentError, "expected 16 bytes, got #{bytes.bytesize}" if bytes.bytesize != 16

        @registers[idx] = bytes.dup
      end

      def read_u64(idx, half) # half: 0=low, 1=high
        @registers[idx].byteslice(half * 8, 8).unpack1("Q<")
      end

      def write_u64(idx, half, value)
        @registers[idx][half * 8, 8] = [value & 0xFFFF_FFFF_FFFF_FFFF].pack("Q<")
      end

      def each_u32(idx)
        4.times.map { |i| @registers[idx].byteslice(i * 4, 4).unpack1("V") }
      end

      def write_u32_lanes(idx, lanes)
        @registers[idx] = lanes.map { |v| [v & 0xFFFF_FFFF].pack("V") }.join
      end

      def each_u8(idx)
        @registers[idx].bytes
      end

      def write_u8_lanes(idx, lanes)
        @registers[idx] = lanes.map { |b| (b & 0xFF).chr }.join.b
      end
    end
  end
end
