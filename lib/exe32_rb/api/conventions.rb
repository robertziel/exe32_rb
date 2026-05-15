# frozen_string_literal: true

module Exe32Rb
  module Api
    # Calling-convention adapters. Each one knows how to read N arguments
    # at the moment a guest CALL has landed on a thunk address, and how to
    # tear down (RAX/EAX-return value + stack-pointer cleanup + RIP=return).
    module Conventions
      # Microsoft x64: RCX, RDX, R8, R9, then 8-byte slots starting at
      # [rsp+0x28] (after the 32-byte shadow space, past the just-pushed
      # return address). Caller cleans up its own stack.
      class MsX64
        ARG_REGS = [
          Emulator::Registers::RCX,
          Emulator::Registers::RDX,
          Emulator::Registers::R8,
          Emulator::Registers::R9,
        ].freeze

        def read_args(machine, n)
          regs = machine.cpu.registers
          out = ARG_REGS.first([n, 4].min).map { |r| regs.read64(r) }
          if n > 4
            rsp = regs.read64(Emulator::Registers::RSP)
            (n - 4).times do |i|
              out << machine.memory.read_u64(rsp + 0x28 + i * 8)
            end
          end
          out
        end

        def return_value(machine, value)
          machine.cpu.registers.write64(Emulator::Registers::RAX, value & 0xFFFF_FFFF_FFFF_FFFF)
        end

        def cleanup(machine, _arg_count)
          machine.cpu.rip = machine.cpu.pop64(machine.memory)
        end
      end

      # Win32 __stdcall: all args on the stack at [esp+4], [esp+8], ...
      # CALLEE pops the args via "ret N".
      class Stdcall32
        def read_args(machine, n)
          esp = machine.cpu.registers.read32(Emulator::Registers::RSP)
          (0...n).map { |i| machine.memory.read_u32(esp + 4 + i * 4) }
        end

        def return_value(machine, value)
          machine.cpu.registers.write32(Emulator::Registers::RAX, value & 0xFFFF_FFFF)
        end

        def cleanup(machine, arg_count)
          esp = machine.cpu.registers.read32(Emulator::Registers::RSP)
          ret = machine.memory.read_u32(esp)
          machine.cpu.registers.write32(Emulator::Registers::RSP, esp + 4 + arg_count * 4)
          machine.cpu.rip = ret
        end
      end

      # Win32 __cdecl: args same as __stdcall but CALLER pops them, so the
      # dispatcher only pops the return address.
      class Cdecl32 < Stdcall32
        def cleanup(machine, _arg_count)
          esp = machine.cpu.registers.read32(Emulator::Registers::RSP)
          ret = machine.memory.read_u32(esp)
          machine.cpu.registers.write32(Emulator::Registers::RSP, esp + 4)
          machine.cpu.rip = ret
        end
      end
    end
  end
end
