# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # A decoded instruction.
    #
    # `mnemonic` is a symbol (:mov, :sub, :lea, :call, :ret, :jmp, :jcc, ...).
    # `operands` is an array of Operand::Reg / ::Mem / ::Imm / ::Rel.
    # `length` is the byte count consumed by the decode (used to advance RIP).
    # `address` is where the instruction was decoded from (for disassembly).
    # `meta` holds extras like {cc: :ne} for Jcc, or {opsize: 64}.
    class Instruction
      attr_reader :address, :mnemonic, :operands, :length, :meta, :raw
      # JIT tier 2: cache the bound method (or nil if not bound yet) so
      # the Executor skips the per-step `send(:op_xxx)` symbol lookup.
      attr_accessor :executor_handle

      def initialize(address:, mnemonic:, operands: [], length:, meta: {}, raw: "")
        @address  = address
        @mnemonic = mnemonic
        @operands = operands
        @length   = length
        @meta     = meta
        @raw      = raw
        @executor_handle = nil
      end

      def to_s
        ops = operands.map(&:to_s).join(", ")
        bytes = raw.bytes.map { |b| format("%02x", b) }.join(" ")
        format("0x%016X  %-24s  %s%s",
               address, bytes, mnemonic, ops.empty? ? "" : " #{ops}")
      end
    end
  end
end
