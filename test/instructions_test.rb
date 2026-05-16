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

  # ------------------------------------------------------------------
  # x87 FPU
  # ------------------------------------------------------------------

  def test_fpu_fld_fadd_fstp_round_trip
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)

    @memory.write(0x60_0000, [1.5].pack("e"))
    @memory.write(0x60_0008, [2.5].pack("e"))
    cpu.registers.write32(0, 0x60_0000)
    cpu.registers.write32(3, 0x60_0008)
    cpu.registers.write32(1, 0x60_0020)

    # fld dword [eax] ; fadd dword [ebx] ; fstp dword [ecx]
    @memory.write(CODE_BASE, [0xD9, 0x00, 0xD8, 0x03, 0xD9, 0x19].pack("C*"))
    3.times { run_one(decoder, executor) }

    result = @memory.read(0x60_0020, 4).unpack1("e")
    assert_in_delta 4.0, result, 1e-6
  end

  def test_fpu_fchs
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.fpu.push(3.5)

    @memory.write(CODE_BASE, [0xD9, 0xE0].pack("C*"))
    run_one(decoder, executor)
    assert_in_delta(-3.5, cpu.fpu.st(0), 1e-6)
  end

  def test_fpu_load_pi_zero_one
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)

    @memory.write(CODE_BASE, [0xD9, 0xE8, 0xD9, 0xEE, 0xD9, 0xEB].pack("C*"))
    3.times { run_one(decoder, executor) }
    assert_in_delta(Math::PI, cpu.fpu.st(0), 1e-12)
    assert_in_delta(0.0,      cpu.fpu.st(1), 1e-12)
    assert_in_delta(1.0,      cpu.fpu.st(2), 1e-12)
  end

  def test_fpu_fild_fistp_m64_preserves_64bit_precision
    # The Delphi RTL's fast 8-byte memcpy uses FILD m64 + FISTP m64 to
    # round-trip 64-bit integers through the FPU. If we store as Float
    # we lose 11 bits of precision; here we assert the round-trip is
    # bit-exact for values that exceed double precision.
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    @memory.write_u64(0x60_0000, 0x0065_0073_0055_002F) # UTF-16LE "/Us\0"
    cpu.registers.write32(0, 0x60_0000)  # eax
    cpu.registers.write32(2, 0x60_0010)  # edx (dst)

    # fild qword [eax]  ; df 28
    # fistp qword [edx] ; df 3a
    @memory.write(CODE_BASE, [0xDF, 0x28, 0xDF, 0x3A].pack("C*"))
    2.times { run_one(decoder, executor) }

    assert_equal 0x0065_0073_0055_002F, @memory.read_u64(0x60_0010),
                 "FILD/FISTP m64 should preserve all 64 bits exactly"
  end

  def test_fpu_faddp
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.fpu.push(2.0); cpu.fpu.push(5.0)

    # DE C1 = faddp st(1), st
    @memory.write(CODE_BASE, [0xDE, 0xC1].pack("C*"))
    run_one(decoder, executor)
    assert_in_delta 7.0, cpu.fpu.st(0), 1e-12
  end

  # ------------------------------------------------------------------
  # SSE / SSE2 — 128-bit XMM
  # ------------------------------------------------------------------

  def test_sse_pxor_clears_xmm
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.xmm.write(0, "\xAA".b * 16)

    # 66 0F EF C0 = pxor xmm0, xmm0
    @memory.write(CODE_BASE, [0x66, 0x0F, 0xEF, 0xC0].pack("C*"))
    run_one(decoder, executor)
    assert_equal "\x00".b * 16, cpu.xmm.read(0)
  end

  def test_sse_movdqa_round_trip_memory
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    # Write a 16-byte pattern to memory
    pattern = (1..16).map(&:chr).join.b
    @memory.write(0x60_0000, pattern)
    cpu.registers.write32(0, 0x60_0000) # eax

    # 66 0F 6F 00  = movdqa xmm0, [eax]
    @memory.write(CODE_BASE, [0x66, 0x0F, 0x6F, 0x00].pack("C*"))
    run_one(decoder, executor)
    assert_equal pattern, cpu.xmm.read(0)
  end

  def test_sse_paddd_lanewise_addition
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.xmm.write(0, [1, 2, 3, 4].pack("V V V V"))
    cpu.xmm.write(1, [10, 20, 30, 40].pack("V V V V"))

    # 66 0F FE C1 = paddd xmm0, xmm1
    @memory.write(CODE_BASE, [0x66, 0x0F, 0xFE, 0xC1].pack("C*"))
    run_one(decoder, executor)
    assert_equal [11, 22, 33, 44], cpu.xmm.read(0).unpack("V V V V")
  end

  def test_sse_pcmpeqb
    decoder, executor = make(32)
    cpu = executor.instance_variable_get(:@cpu)
    cpu.xmm.write(0, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10".b)
    cpu.xmm.write(1, "\x01\xFF\x03\xFF\x05\xFF\x07\xFF\x09\xFF\x0B\xFF\x0D\xFF\x0F\xFF".b)

    # 66 0F 74 C1 = pcmpeqb xmm0, xmm1
    @memory.write(CODE_BASE, [0x66, 0x0F, 0x74, 0xC1].pack("C*"))
    run_one(decoder, executor)
    # bytes that matched become 0xFF, others 0x00
    assert_equal "\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00\xFF\x00".b,
                 cpu.xmm.read(0)
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
