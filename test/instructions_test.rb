# frozen_string_literal: true

require_relative "test_helper"

# Unit tests for the x86 decoder + executor primitives. Each test wires up
# just enough state — memory + CPU + executor — to exercise one code path
# without going through PE loading or Machine.
class InstructionsTest < Minitest::Test
  CODE_BASE = 0x40_1000

  def setup
    @memory = Exe32Rb::Emulator::Memory.new
    @memory.map(CODE_BASE, 0x1000, name: "code")
    @memory.map(0x60_0000, 0x10000, name: "data")
  end

  # ------------------------------------------------------------------
  # 32-bit-mode primitives
  # ------------------------------------------------------------------

  def test_i386_inc_dec_short_form
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)

    @memory.write(CODE_BASE, [0x40, 0x4F].pack("C*"))
    cpu.registers.write32(0, 10)
    cpu.registers.write32(7, 5)

    run_one(decoder, executor)
    run_one(decoder, executor)

    assert_equal 11, cpu.registers.read32(0)
    assert_equal 4,  cpu.registers.read32(7)
  end

  def test_i386_call_indirect_through_absolute_disp32
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.rsp = 0x70_FF00
    @memory.map(0x70_0000, 0x1_0000, name: "stack")

    @memory.write_u32(0x60_0000, 0x40_5000)
    @memory.map(0x40_5000, 0x1000, name: "target")

    @memory.write(CODE_BASE, [0xFF, 0x15, 0x00, 0x00, 0x60, 0x00].pack("C*"))
    run_one(decoder, executor)

    assert_equal 0x40_5000, cpu.rip
    assert_equal CODE_BASE + 6, @memory.read_u32(cpu.rsp)
  end

  # ------------------------------------------------------------------
  # FS segment + TIB-like access
  # ------------------------------------------------------------------

  def test_fs_segment_access
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)

    tib_base = 0x6E_0000
    @memory.map(tib_base, 0x1000, name: "tib")
    @memory.write_u32(tib_base + 0x00, 0xFFFF_FFFF)
    cpu.fs_base = tib_base
    cpu.registers.write32(2, 0)

    @memory.write(CODE_BASE, [0x64, 0x8B, 0x02].pack("C*"))
    run_one(decoder, executor)

    assert_equal 0xFFFF_FFFF, cpu.registers.read32(0)
  end

  # ------------------------------------------------------------------
  # New executor mnemonics
  # ------------------------------------------------------------------

  def test_div_32bit
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.registers.write32(2, 0)
    cpu.registers.write32(0, 100)
    cpu.registers.write32(1, 7)
    @memory.write(CODE_BASE, [0xF7, 0xF1].pack("C*"))
    run_one(decoder, executor)

    assert_equal 14, cpu.registers.read32(0)
    assert_equal 2,  cpu.registers.read32(2)
  end

  def test_xchg_eax_with_register
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.registers.write32(0, 0x1111_AAAA)
    cpu.registers.write32(3, 0x2222_BBBB)

    @memory.write(CODE_BASE, [0x93].pack("C*"))
    run_one(decoder, executor)

    assert_equal 0x2222_BBBB, cpu.registers.read32(0)
    assert_equal 0x1111_AAAA, cpu.registers.read32(3)
  end

  def test_rep_stosd_clears_buffer
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    @memory.map(0x6F_0000, 0x1000, name: "buffer")

    cpu.registers.write32(0, 0xDEAD_BEEF)
    cpu.registers.write32(7, 0x6F_0000)
    cpu.registers.write32(1, 4)
    cpu.flags.df = false

    @memory.write(CODE_BASE, [0xF3, 0xAB].pack("C*"))
    run_one(decoder, executor)

    4.times do |i|
      assert_equal 0xDEAD_BEEF, @memory.read_u32(0x6F_0000 + i * 4)
    end
    assert_equal 0x6F_0010, cpu.registers.read32(7)
    assert_equal 0,         cpu.registers.read32(1)
  end

  def test_test_dl_imm8_does_not_overread
    decoder, _executor = make(32)
    @memory.write(CODE_BASE, [0xF6, 0xC2, 0x07, 0x90, 0x90].pack("C*"))
    inst = decoder.decode(CODE_BASE)
    assert_equal :test, inst.mnemonic
    assert_equal 3,     inst.length
  end

  # ------------------------------------------------------------------
  # Decoder mode-specific addressing
  # ------------------------------------------------------------------

  def test_rip_relative_only_in_64bit_mode
    @memory.write(CODE_BASE, [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00].pack("C*"))
    d64 = Exe32Rb::Emulator::Decoder.new(@memory, mode: 64)
    op64 = d64.decode(CODE_BASE).operands[1]
    assert op64.rip_relative

    @memory.write(CODE_BASE, [0x8B, 0x05, 0x10, 0x00, 0x60, 0x00].pack("C*"))
    d32 = Exe32Rb::Emulator::Decoder.new(@memory, mode: 32)
    op32 = d32.decode(CODE_BASE).operands[1]
    refute op32.rip_relative
    assert_equal 0x60_0010, op32.disp
  end

  private

  def make(mode)
    cpu = Exe32Rb::Emulator::CPU.new(mode: mode)
    cpu.rip = CODE_BASE
    decoder = Exe32Rb::Emulator::Decoder.new(@memory, mode: mode)
    executor = Exe32Rb::Emulator::Executor.new(cpu, @memory)
    [decoder, executor]
  end

  def run_one(decoder, executor)
    cpu = executor.instance_variable_get(:@cpu)
    inst = decoder.decode(cpu.rip)
    cpu.rip = (cpu.rip + inst.length) & cpu.address_mask
    executor.execute(inst)
  end
end
