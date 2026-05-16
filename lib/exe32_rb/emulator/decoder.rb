# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # x86_64 instruction decoder.
    #
    # Reads bytes from Memory starting at a given RIP and produces an
    # Instruction value (mnemonic + operands + length). Designed to grow:
    # opcode dispatch is a single case, helpers cover prefix/ModR/M/SIB/disp,
    # and adding an opcode means adding one method and one case arm.
    #
    # Coverage is a useful baseline rather than complete:
    # * Arithmetic groups: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP (00..3D)
    # * MOV variants: 88/89/8A/8B, B0..BF, C6/C7
    # * LEA (8D)
    # * TEST (84/85), F7 group (TEST imm, NEG, NOT, MUL, IMUL, DIV, IDIV)
    # * INC/DEC/CALL/JMP/PUSH via group 5 (FF)
    # * PUSH/POP r64 (50..5F), PUSH imm8/imm32 (6A/68)
    # * Group 1 immediates (80/81/83)
    # * Group 2 shifts (D0/D1/D2/D3/C0/C1) — SHL/SHR/SAR/ROL/ROR/RCL/RCR
    # * Branches: rel8 Jcc (70..7F), rel32 Jcc (0F 80..8F), JMP rel (E9/EB),
    #   CALL rel (E8), RET near (C2/C3)
    # * Two-byte MOVZX/MOVSX (0F B6/B7/BE/BF)
    # * NOP (90, 0F 1F), INT3 (CC), HLT (F4)
    # * SYSCALL (0F 05) is decoded but executor treats as illegal.
    class Decoder
      def initialize(memory, mode: 64)
        @memory = memory
        @mode   = mode
      end

      def decode(address)
        Context.new(@memory, address, @mode).decode!
      end

      class Context
        REX_W = 0x08
        REX_R = 0x04
        REX_X = 0x02
        REX_B = 0x01

        GROUP1 = %i[add or adc sbb and sub xor cmp].freeze
        GROUP2 = %i[rol ror rcl rcr shl shr sal sar].freeze

        CC_NAMES = %i[o no b ae e ne be a s ns p np l ge le g].freeze

        def initialize(memory, address, mode)
          @memory  = memory
          @address = address
          @cursor  = address
          @mode    = mode
          @raw     = +"".b
          @rex          = 0
          @rex_present  = false
          @opsize_over  = false
          @addrsize_over = false
          @rep_prefix   = nil
          @lock_prefix  = false
          @seg_override = nil
        end

        def decode!
          consume_prefixes
          opcode = read_u8
          inst = if opcode == 0x0F
                   decode_two_byte(read_u8)
                 else
                   decode_one_byte(opcode)
                 end
          inst
        end

        # ------------------------------------------------------------------
        # Prefixes
        # ------------------------------------------------------------------

        def consume_prefixes
          loop do
            b = peek_u8
            case b
            when 0x66 then @opsize_over   = true; consume_byte
            when 0x67 then @addrsize_over = true; consume_byte
            when 0xF0 then @lock_prefix   = true; consume_byte
            when 0xF2 then @rep_prefix = :repne; consume_byte
            when 0xF3 then @rep_prefix = :rep;   consume_byte
            when 0x26, 0x2E, 0x36, 0x3E then @seg_override = b; consume_byte
            when 0x64 then @seg_override = :fs; consume_byte
            when 0x65 then @seg_override = :gs; consume_byte
            when 0x40..0x4F
              # REX prefix only exists in 64-bit mode; in 32-bit mode
              # these bytes are INC/DEC r32 opcodes — leave them for
              # the main decode pass.
              if @mode == 64
                @rex = b
                @rex_present = true
                consume_byte
              end
              return
            else
              return
            end
          end
        end

        # ------------------------------------------------------------------
        # Top-level opcode dispatch
        # ------------------------------------------------------------------

        def decode_one_byte(opcode)
          case opcode
          when 0x00..0x05 then arith_group(:add, opcode)
          when 0x08..0x0D then arith_group(:or,  opcode)
          when 0x10..0x15 then arith_group(:adc, opcode)
          when 0x18..0x1D then arith_group(:sbb, opcode)
          when 0x20..0x25 then arith_group(:and, opcode)
          when 0x28..0x2D then arith_group(:sub, opcode)
          when 0x30..0x35 then arith_group(:xor, opcode)
          when 0x38..0x3D then arith_group(:cmp, opcode)
          when 0x40..0x47 then inc_r_short(opcode)   # 32-bit mode only (REX in 64-bit)
          when 0x48..0x4F then dec_r_short(opcode)   # 32-bit mode only (REX in 64-bit)
          when 0x50..0x57 then push_r64_short(opcode)
          when 0x58..0x5F then pop_r64_short(opcode)
          when 0x63       then movsxd
          when 0x68       then push_imm32
          when 0x69       then imul_three_op(imm_size: imm_size_z(operand_size_v))
          when 0x6A       then push_imm8
          when 0x6B       then imul_three_op(imm_size: 8)
          when 0x70..0x7F then jcc_rel8(opcode)
          when 0x80       then group1(8, imm_size: 8)
          when 0x81       then group1(operand_size_v, imm_size: imm_size_z(operand_size_v))
          when 0x83       then group1(operand_size_v, imm_size: 8, sign_extend: true)
          when 0x84       then test_modrm(8)
          when 0x85       then test_modrm(operand_size_v)
          when 0x86       then xchg_modrm(8)
          when 0x87       then xchg_modrm(operand_size_v)
          when 0x88       then mov_rm_r(8)
          when 0x89       then mov_rm_r(operand_size_v)
          when 0x8A       then mov_r_rm(8)
          when 0x8B       then mov_r_rm(operand_size_v)
          when 0x8D       then lea
          when 0x8F       then group_8f
          when 0x90       then nop                       # NOP (also XCHG eAX, eAX)
          when 0x91..0x97 then xchg_acc_r(opcode)
          when 0x98       then cdqe_or_cwde_or_cbw
          when 0x9B       then simple(:fpu_nop) # FWAIT
          when 0x9E       then simple(:sahf)    # store AH into low byte of FLAGS
          when 0x9F       then simple(:lahf)    # load AH from low byte of FLAGS
          when 0xA0       then mov_acc_moffs(8, dst_is_acc: true)
          when 0xA1       then mov_acc_moffs(operand_size_v, dst_is_acc: true)
          when 0xA2       then mov_acc_moffs(8, dst_is_acc: false)
          when 0xA3       then mov_acc_moffs(operand_size_v, dst_is_acc: false)
          when 0xA4       then string_op(:movs, 8)
          when 0xA5       then string_op(:movs, operand_size_v)
          when 0xA6       then string_op(:cmps, 8)
          when 0xA7       then string_op(:cmps, operand_size_v)
          when 0xAA       then string_op(:stos, 8)
          when 0xAB       then string_op(:stos, operand_size_v)
          when 0xAC       then string_op(:lods, 8)
          when 0xAD       then string_op(:lods, operand_size_v)
          when 0xAE       then string_op(:scas, 8)
          when 0xAF       then string_op(:scas, operand_size_v)
          when 0x99       then cqo_or_cdq_or_cwd
          when 0xA8       then test_acc_imm(8)
          when 0xA9       then test_acc_imm(operand_size_v)
          when 0xB0..0xB7 then mov_r8_imm(opcode)
          when 0xB8..0xBF then mov_r_imm(opcode)
          when 0xC0       then group2(8, imm_kind: :imm8)
          when 0xC1       then group2(operand_size_v, imm_kind: :imm8)
          when 0xC2       then ret_imm16
          when 0xC3       then simple(:ret)
          when 0xC6       then mov_rm_imm(8)
          when 0xC7       then mov_rm_imm(operand_size_v)
          when 0xCC       then simple(:int3)
          when 0xCD       then int_imm8
          when 0xD0       then group2(8, imm_kind: :one)
          when 0xD1       then group2(operand_size_v, imm_kind: :one)
          when 0xD2       then group2(8, imm_kind: :cl)
          when 0xD3       then group2(operand_size_v, imm_kind: :cl)
          when 0xD8..0xDF then fpu_instr(opcode)
          when 0xE8       then call_rel32
          when 0xE9       then jmp_rel32
          when 0xEB       then jmp_rel8
          when 0xF4       then simple(:hlt)
          when 0xF6       then group_f6f7(8)
          when 0xF7       then group_f6f7(operand_size_v)
          when 0xF8       then simple(:clc)
          when 0xF9       then simple(:stc)
          when 0xFC       then simple(:cld)
          when 0xFD       then simple(:std)
          when 0xFE       then group_fe
          when 0xFF       then group5
          else
            raise Exe32Rb::DecodeError, format("unsupported opcode 0x%02X at 0x%X", opcode, @address)
          end
        end

        def decode_two_byte(opcode2)
          case opcode2
          when 0x05            then simple(:syscall)
          when 0x1F            then nop_long
          when 0x31            then simple(:rdtsc)
          when 0x80..0x8F      then jcc_rel32(opcode2)
          when 0x90..0x9F      then setcc(opcode2)
          when 0xB6            then movzx(src: 8)
          when 0xB7            then movzx(src: 16)
          when 0xBE            then movsx(src: 8)
          when 0xBF            then movsx(src: 16)
          when 0xAF            then imul_two_op
          # SSE/SSE2 — operand selection depends on prefix:
          #   no prefix → packed-single / scalar-single
          #   0x66      → packed-double / 128-bit integer SIMD
          #   0xF3      → scalar-single REP variant / movdqu
          #   0xF2      → scalar-double REP variant
          when 0x10, 0x11      then sse_movups(opcode2)
          when 0x28, 0x29      then sse_movaps(opcode2)
          when 0x6E            then sse_movd(opcode2)
          when 0x6F, 0x7F      then sse_movdq(opcode2)
          when 0x7E            then sse_movd_or_movq(opcode2)
          when 0x57            then sse_packed(:xorps)
          when 0x54            then sse_packed(:andps)
          when 0x55            then sse_packed(:andnps)
          when 0x56            then sse_packed(:orps)
          when 0xEF            then sse_packed(:pxor)
          when 0xDB            then sse_packed(:pand)
          when 0xDF            then sse_packed(:pandn)
          when 0xEB            then sse_packed(:por)
          when 0xFE            then sse_packed(:paddd)
          when 0xFC            then sse_packed(:paddb)
          when 0xFD            then sse_packed(:paddw)
          when 0xFA            then sse_packed(:psubd)
          when 0xF8            then sse_packed(:psubb)
          when 0xF9            then sse_packed(:psubw)
          when 0x74            then sse_packed(:pcmpeqb)
          when 0x75            then sse_packed(:pcmpeqw)
          when 0x76            then sse_packed(:pcmpeqd)
          else
            raise Exe32Rb::DecodeError, format("unsupported 0F %02X at 0x%X", opcode2, @address)
          end
        end

        # Generic packed-128 SSE2 instruction: xmm, xmm/m128
        # We require the 0x66 prefix here (integer SIMD variant).
        # Non-prefixed forms typically apply to packed floats; we treat
        # both the same since most Ruby implementations mirror the
        # bitwise/integer operation regardless.
        def sse_packed(mnem)
          reg_op, rm_op = decode_modrm(128)
          instr(mnem, [reg_op, rm_op])
        end

        def sse_movups(opcode2)
          reg_op, rm_op = decode_modrm(128)
          if opcode2 == 0x10
            instr(:movups, [reg_op, rm_op])
          else
            instr(:movups, [rm_op, reg_op])
          end
        end

        def sse_movaps(opcode2)
          reg_op, rm_op = decode_modrm(128)
          if opcode2 == 0x28
            instr(:movaps, [reg_op, rm_op])
          else
            instr(:movaps, [rm_op, reg_op])
          end
        end

        # 66 0F 6E /r = MOVD xmm, r/m32 — dst is xmm (128), src is r/m32
        def sse_movd(_opcode2)
          field = (peek_u8 >> 3) & 0x7
          reg_idx = field
          _, rm_op = decode_modrm(32)
          dst = Operand::Reg.new(size: 128, idx: reg_idx, high_byte: false)
          instr(:movd, [dst, rm_op])
        end

        # 66 0F 7E /r = MOVD r/m32, xmm  (move xmm->r/m32)
        # F3 0F 7E /r = MOVQ xmm, xmm/m64
        def sse_movd_or_movq(_opcode2)
          if @rep_prefix == :rep # F3 prefix → MOVQ
            reg_op, rm_op = decode_modrm(128)
            instr(:movq, [reg_op, rm_op])
          else                    # 66 or none → MOVD
            field = (peek_u8 >> 3) & 0x7
            reg_idx = field
            _, rm_op = decode_modrm(32)
            src = Operand::Reg.new(size: 128, idx: reg_idx, high_byte: false)
            instr(:movd, [rm_op, src])
          end
        end

        # 66 0F 6F /r = MOVDQA  ; F3 0F 6F /r = MOVDQU  ; 7F = reverse direction
        def sse_movdq(opcode2)
          reg_op, rm_op = decode_modrm(128)
          mnem = (@rep_prefix == :rep) ? :movdqu : :movdqa
          if opcode2 == 0x6F
            instr(mnem, [reg_op, rm_op])
          else
            instr(mnem, [rm_op, reg_op])
          end
        end

        # ------------------------------------------------------------------
        # Common decoded encodings
        # ------------------------------------------------------------------

        # opcode lower bits select among 6 standard encodings for the binary
        # arithmetic mnemonics: r/m8,r8 / r/m,r / r8,r/m8 / r,r/m / AL,imm8 / rAX,immv.
        def arith_group(mnem, opcode)
          case opcode & 0x07
          when 0x0
            reg_op, rm_op = decode_modrm(8)
            instr(mnem, [rm_op, reg_op])
          when 0x1
            sz = operand_size_v
            reg_op, rm_op = decode_modrm(sz)
            instr(mnem, [rm_op, reg_op])
          when 0x2
            reg_op, rm_op = decode_modrm(8)
            instr(mnem, [reg_op, rm_op])
          when 0x3
            sz = operand_size_v
            reg_op, rm_op = decode_modrm(sz)
            instr(mnem, [reg_op, rm_op])
          when 0x4
            imm = decode_imm(8, signed: false)
            instr(mnem, [build_reg(8, 0), imm])
          when 0x5
            sz = operand_size_v
            imm_sz = imm_size_z(sz)
            imm = decode_imm(imm_sz, signed: sz == 64)
            instr(mnem, [build_reg(sz, 0), imm])
          end
        end

        def mov_rm_r(size)
          reg_op, rm_op = decode_modrm(size)
          instr(:mov, [rm_op, reg_op])
        end

        def mov_r_rm(size)
          reg_op, rm_op = decode_modrm(size)
          instr(:mov, [reg_op, rm_op])
        end

        def lea
          sz = operand_size_v
          reg_op, rm_op = decode_modrm(sz)
          raise Exe32Rb::DecodeError, "LEA with register operand at 0x#{@address.to_s(16)}" unless rm_op.is_a?(Operand::Mem)

          instr(:lea, [reg_op, rm_op])
        end

        # A0/A1/A2/A3: MOV between accumulator and an absolute "moffs" address.
        # The address has no ModR/M — it's just an immediate of address-size width.
        def mov_acc_moffs(operand_size, dst_is_acc:)
          addr = read_address_imm
          mem  = Operand::Mem.new(size: operand_size, base: nil, index: nil,
                                  scale: 1, disp: addr, rip_relative: false,
                                  seg: segment_for_mem)
          acc  = build_reg(operand_size, 0)
          ops  = dst_is_acc ? [acc, mem] : [mem, acc]
          instr(:mov, ops)
        end

        def read_address_imm
          # Address-size is mode-native (16 in i386 with 0x67, 32 in long mode
          # with 0x67, etc.); we honor the default-for-mode here, which is
          # what every real compiler emits.
          case @mode
          when 64 then read_u64
          when 32 then @addrsize_over ? read_u16 : read_u32
          end
        end

        def mov_r_imm(opcode)
          sz = operand_size_v
          reg_idx = (opcode & 0x07) | ((@rex & REX_B) != 0 ? 0x8 : 0)
          imm = decode_imm(sz, signed: false)
          instr(:mov, [build_reg(sz, reg_idx), imm])
        end

        def mov_r8_imm(opcode)
          reg_idx = (opcode & 0x07) | ((@rex & REX_B) != 0 ? 0x8 : 0)
          imm = decode_imm(8, signed: false)
          instr(:mov, [build_reg(8, reg_idx), imm])
        end

        def mov_rm_imm(size)
          field, _reg, rm_op = decode_modrm_with_field(size)
          raise Exe32Rb::DecodeError, "C6/C7 with /#{field}" unless field == 0

          # C6 is MOV r/m8, imm8. C7 is MOV r/m{v}, imm{z(v)} — sign-extended
          # to 64 bits when REX.W. Don't run the imm8 form through imm_size_z
          # or it'll mis-read 4 bytes.
          imm_sz = size == 8 ? 8 : imm_size_z(size)
          imm = decode_imm(imm_sz, signed: size == 64)
          instr(:mov, [rm_op, imm])
        end

        def group1(operand_size, imm_size:, sign_extend: false)
          field, _reg, rm_op = decode_modrm_with_field(operand_size)
          mnem = GROUP1[field]
          imm = decode_imm(imm_size, signed: sign_extend || imm_size < operand_size)
          instr(mnem, [rm_op, imm])
        end

        def group2(operand_size, imm_kind:)
          field, _reg, rm_op = decode_modrm_with_field(operand_size)
          mnem = GROUP2[field]
          right = case imm_kind
                  when :imm8 then decode_imm(8, signed: false)
                  when :one  then Operand::Imm.new(size: 8, value: 1, signed: false)
                  when :cl   then build_reg(8, 1) # CL
                  end
          instr(mnem, [rm_op, right])
        end

        def group_f6f7(size)
          field, _reg, rm_op = decode_modrm_with_field(size)
          case field
          when 0, 1
            imm_sz = imm_size_z(size)
            imm = decode_imm(imm_sz, signed: false)
            instr(:test, [rm_op, imm])
          when 2 then instr(:not, [rm_op])
          when 3 then instr(:neg, [rm_op])
          when 4 then instr(:mul,  [rm_op])
          when 5 then instr(:imul, [rm_op])
          when 6 then instr(:div,  [rm_op])
          when 7 then instr(:idiv, [rm_op])
          end
        end

        def group_fe
          field, _reg, rm_op = decode_modrm_with_field(8)
          case field
          when 0 then instr(:inc, [rm_op])
          when 1 then instr(:dec, [rm_op])
          else raise Exe32Rb::DecodeError, "FE /#{field} unsupported"
          end
        end

        def group_8f
          field, _reg, rm_op = decode_modrm_with_field(64)
          raise Exe32Rb::DecodeError, "8F /#{field}" unless field == 0

          instr(:pop, [rm_op])
        end

        def group5
          byte = peek_u8
          field = (byte >> 3) & 0x7
          size = case field
                 when 0, 1 then operand_size_v
                 else stack_default_size # near CALL/JMP/PUSH operand width
                 end
          _, _reg, rm_op = decode_modrm_with_field(size)
          case field
          when 0 then instr(:inc, [rm_op])
          when 1 then instr(:dec, [rm_op])
          when 2 then instr(:call_indirect, [rm_op])
          when 4 then instr(:jmp_indirect, [rm_op])
          when 6 then instr(:push, [rm_op])
          else raise Exe32Rb::DecodeError, "FF /#{field} unsupported"
          end
        end

        def test_modrm(size)
          reg_op, rm_op = decode_modrm(size)
          instr(:test, [rm_op, reg_op])
        end

        def xchg_modrm(size)
          reg_op, rm_op = decode_modrm(size)
          instr(:xchg, [rm_op, reg_op])
        end

        def xchg_acc_r(opcode)
          sz = operand_size_v
          reg_idx = (opcode & 0x07) | ((@rex & REX_B) != 0 ? 0x8 : 0)
          instr(:xchg, [build_reg(sz, 0), build_reg(sz, reg_idx)])
        end

        def string_op(mnemonic, size)
          instr(mnemonic, [], op_size: size, rep: @rep_prefix)
        end

        def test_acc_imm(size)
          imm_sz = imm_size_z(size)
          imm = decode_imm(imm_sz, signed: false)
          instr(:test, [build_reg(size, 0), imm])
        end

        def push_r64_short(opcode)
          idx = (opcode & 0x07) | ((@rex & REX_B) != 0 ? 0x8 : 0)
          # PUSH/POP default to native stack width: 64 in long mode, 32 in i386.
          size = stack_default_size
          instr(:push, [build_reg(size, idx)])
        end

        def pop_r64_short(opcode)
          idx = (opcode & 0x07) | ((@rex & REX_B) != 0 ? 0x8 : 0)
          size = stack_default_size
          instr(:pop, [build_reg(size, idx)])
        end

        def inc_r_short(opcode)
          idx = opcode & 0x07
          instr(:inc, [build_reg(operand_size_v, idx)])
        end

        def dec_r_short(opcode)
          idx = opcode & 0x07
          instr(:dec, [build_reg(operand_size_v, idx)])
        end

        def stack_default_size
          @mode == 64 ? 64 : 32
        end

        # x87 FPU instructions (opcodes 0xD8..0xDF). Each opcode has a
        # ModR/M byte; if mod != 3 the operand is memory (with usual
        # SIB/disp encoding) and the reg field selects the sub-op.
        # If mod == 3 the full ModR/M byte (rest of E0..FF range) is
        # itself the sub-op selector.
        def fpu_instr(opcode)
          byte = peek_u8
          mod = (byte >> 6) & 0x3
          if mod == 3
            full = byte
            consume_byte
            decode_fpu_reg_op(opcode, full)
          else
            field = (byte >> 3) & 0x7
            _, _reg, rm_op = decode_modrm_with_field(fpu_mem_size(opcode))
            decode_fpu_mem_op(opcode, field, rm_op)
          end
        end

        # mod != 3 case — the memory operand size depends on the opcode:
        #   D8 / DA: m32 (single / int32)
        #   D9       m32 (FLD/FST/FSTP) / m16 (FLDCW/FNSTCW) / m14 (FLDENV)
        #   DB       m32 (int) / m80 (FLD/FSTP TBYTE)
        #   DC / DF  m64 (double / int64) / DF int16
        # We default to 32 since the executor reads the right number of
        # bytes itself via the mnemonic; only the disp/SIB byte count matters
        # for decoding, and it's identical for m16/m32/m64/m80.
        def fpu_mem_size(_opcode); 32; end

        FPU_MEM_DISPATCH = {
          0xD8 => %i[fadd_m32 fmul_m32 fcom_m32 fcomp_m32 fsub_m32 fsubr_m32 fdiv_m32 fdivr_m32],
          0xD9 => %i[fld_m32 fpu_nop fst_m32 fstp_m32 fldenv fldcw_m16 fnstenv fnstcw_m16],
          0xDA => %i[fiadd_m32 fimul_m32 ficom_m32 ficomp_m32 fisub_m32 fisubr_m32 fidiv_m32 fidivr_m32],
          0xDB => %i[fild_m32 fpu_nop fist_m32 fistp_m32 fpu_nop fld_m80 fpu_nop fstp_m80],
          0xDC => %i[fadd_m64 fmul_m64 fcom_m64 fcomp_m64 fsub_m64 fsubr_m64 fdiv_m64 fdivr_m64],
          0xDD => %i[fld_m64 fisttp_m64 fst_m64 fstp_m64 frstor fpu_nop fnsave fnstsw_m16],
          0xDE => %i[fiadd_m16 fimul_m16 ficom_m16 ficomp_m16 fisub_m16 fisubr_m16 fidiv_m16 fidivr_m16],
          0xDF => %i[fild_m16 fisttp_m16 fist_m16 fistp_m16 fbld fild_m64 fbstp fistp_m64],
        }.freeze

        def decode_fpu_mem_op(opcode, field, mem)
          mnem = FPU_MEM_DISPATCH[opcode][field] || :fpu_nop
          instr(mnem, [mem])
        end

        def decode_fpu_reg_op(opcode, full)
          sti = full & 0x7
          # mod==3 form: full ModR/M byte uniquely identifies the operation.
          case opcode
          when 0xD8
            case full & 0xF8
            when 0xC0 then instr(:fadd_st,  [build_reg(80, 0), build_reg(80, sti)])
            when 0xC8 then instr(:fmul_st,  [build_reg(80, 0), build_reg(80, sti)])
            when 0xD0 then instr(:fcom_st,  [build_reg(80, sti)])
            when 0xD8 then instr(:fcomp_st, [build_reg(80, sti)])
            when 0xE0 then instr(:fsub_st,  [build_reg(80, 0), build_reg(80, sti)])
            when 0xE8 then instr(:fsubr_st, [build_reg(80, 0), build_reg(80, sti)])
            when 0xF0 then instr(:fdiv_st,  [build_reg(80, 0), build_reg(80, sti)])
            when 0xF8 then instr(:fdivr_st, [build_reg(80, 0), build_reg(80, sti)])
            else instr(:fpu_nop, [])
            end
          when 0xD9
            case full
            when 0xC0..0xC7 then instr(:fld_st, [build_reg(80, sti)])
            when 0xC8..0xCF then instr(:fxch,   [build_reg(80, sti)])
            when 0xD0       then instr(:fpu_nop, [])
            when 0xE0       then instr(:fchs, [])
            when 0xE1       then instr(:fabs, [])
            when 0xE4       then instr(:ftst, [])
            when 0xE8       then instr(:fld1, [])
            when 0xE9       then instr(:fldl2t, [])
            when 0xEA       then instr(:fldl2e, [])
            when 0xEB       then instr(:fldpi, [])
            when 0xEC       then instr(:fldlg2, [])
            when 0xED       then instr(:fldln2, [])
            when 0xEE       then instr(:fldz, [])
            else instr(:fpu_nop, [])
            end
          when 0xDD
            case full & 0xF8
            when 0xC0 then instr(:ffree, [build_reg(80, sti)])
            when 0xD0 then instr(:fst_st, [build_reg(80, sti)])
            when 0xD8 then instr(:fstp_st, [build_reg(80, sti)])
            when 0xE0 then instr(:fucom, [build_reg(80, sti)])
            when 0xE8 then instr(:fucomp, [build_reg(80, sti)])
            else instr(:fpu_nop, [])
            end
          when 0xDE
            case full
            when 0xC0..0xC7 then instr(:faddp,  [build_reg(80, sti)])
            when 0xC8..0xCF then instr(:fmulp,  [build_reg(80, sti)])
            when 0xD9       then instr(:fcompp, [])
            when 0xE0..0xE7 then instr(:fsubrp, [build_reg(80, sti)])
            when 0xE8..0xEF then instr(:fsubp,  [build_reg(80, sti)])
            when 0xF0..0xF7 then instr(:fdivrp, [build_reg(80, sti)])
            when 0xF8..0xFF then instr(:fdivp,  [build_reg(80, sti)])
            else instr(:fpu_nop, [])
            end
          when 0xDF
            case full
            when 0xE0 then instr(:fnstsw_ax, [])
            else instr(:fpu_nop, [])
            end
          else
            instr(:fpu_nop, [])
          end
        end

        def push_imm8
          imm = decode_imm(8, signed: true)
          instr(:push, [imm])
        end

        def push_imm32
          imm = decode_imm(32, signed: true)
          instr(:push, [imm])
        end

        def ret_imm16
          imm = decode_imm(16, signed: false)
          instr(:ret, [imm])
        end

        def int_imm8
          imm = decode_imm(8, signed: false)
          instr(:int, [imm])
        end

        def call_rel32
          rel = decode_rel(32)
          instr(:call, [rel])
        end

        def jmp_rel32
          rel = decode_rel(32)
          instr(:jmp, [rel])
        end

        def jmp_rel8
          rel = decode_rel(8)
          instr(:jmp, [rel])
        end

        def jcc_rel8(opcode)
          rel = decode_rel(8)
          instr(:jcc, [rel], cc: CC_NAMES[opcode & 0x0F])
        end

        def jcc_rel32(opcode2)
          rel = decode_rel(32)
          instr(:jcc, [rel], cc: CC_NAMES[opcode2 & 0x0F])
        end

        def setcc(opcode2)
          _, _reg, rm_op = decode_modrm_with_field(8)
          instr(:setcc, [rm_op], cc: CC_NAMES[opcode2 & 0x0F])
        end

        def movsxd
          decode_dual_size(:movsxd, dst_size: operand_size_v, src_size: 32)
        end

        def cdqe_or_cwde_or_cbw
          # 98: CBW (16-bit), CWDE (32-bit), CDQE (64-bit) — sign-extend rAX
          sz = operand_size_v
          mnem = case sz
                 when 16 then :cbw
                 when 32 then :cwde
                 when 64 then :cdqe
                 end
          simple(mnem)
        end

        def cqo_or_cdq_or_cwd
          sz = operand_size_v
          mnem = case sz
                 when 16 then :cwd
                 when 32 then :cdq
                 when 64 then :cqo
                 end
          simple(mnem)
        end

        def movzx(src:)
          decode_dual_size(:movzx, dst_size: operand_size_v, src_size: src)
        end

        def movsx(src:)
          decode_dual_size(:movsx, dst_size: operand_size_v, src_size: src)
        end

        # Decode an instruction whose reg operand has one size and rm operand
        # has another (MOVZX/MOVSX/MOVSXD). We peek ModR/M to grab the reg
        # field, then run the full ModR/M decode using the rm operand size,
        # and finally synthesize a properly-sized reg operand.
        def decode_dual_size(mnemonic, dst_size:, src_size:)
          modrm = peek_u8
          reg_field = (modrm >> 3) & 0x7
          reg_idx = reg_field | ((@rex & REX_R) != 0 ? 0x8 : 0)
          _ignored, rm_op = decode_modrm(src_size)
          dst_reg = build_reg(dst_size, reg_idx)
          instr(mnemonic, [dst_reg, rm_op])
        end

        def imul_two_op
          sz = operand_size_v
          reg_op, rm_op = decode_modrm(sz)
          instr(:imul, [reg_op, rm_op])
        end

        # 69 /r iz: IMUL r{v}, r/m{v}, imm{z}
        # 6B /r ib: IMUL r{v}, r/m{v}, imm8 (sign-extended)
        def imul_three_op(imm_size:)
          sz = operand_size_v
          reg_op, rm_op = decode_modrm(sz)
          imm = decode_imm(imm_size, signed: true)
          instr(:imul, [reg_op, rm_op, imm])
        end

        def nop
          instr(:nop, [])
        end

        def nop_long
          # 0F 1F /0: multi-byte NOP — decode the ModR/M just to advance.
          _, _reg, _rm = decode_modrm_with_field(operand_size_v)
          instr(:nop, [])
        end

        def simple(mnem)
          instr(mnem, [])
        end

        # ------------------------------------------------------------------
        # ModR/M, SIB, displacement decoding
        # ------------------------------------------------------------------

        def decode_modrm(operand_size)
          @last_modrm_offset = @cursor
          byte = read_u8
          mod = (byte >> 6) & 0x3
          reg = (byte >> 3) & 0x7
          rm  = byte & 0x7

          reg |= 0x8 if (@rex & REX_R) != 0
          reg_op = build_reg(operand_size, reg)

          rm_op = if mod == 3
                    rm_full = rm | ((@rex & REX_B) != 0 ? 0x8 : 0)
                    build_reg(operand_size, rm_full)
                  else
                    decode_modrm_mem(mod, rm, operand_size)
                  end
          [reg_op, rm_op]
        end

        def decode_modrm_with_field(operand_size)
          field = (peek_u8 >> 3) & 0x7
          reg_op, rm_op = decode_modrm(operand_size)
          [field, reg_op, rm_op]
        end

        def rewind_modrm
          consumed = @cursor - @last_modrm_offset
          @cursor -= consumed
          @raw = @raw.byteslice(0, @raw.bytesize - consumed)
        end

        def decode_modrm_mem(mod, rm, mem_size)
          if mod == 0 && rm == 5
            # In 64-bit mode this is RIP-relative; in 32-bit mode it's an
            # absolute disp32 with no base register.
            disp = read_i32
            return Operand::Mem.new(size: mem_size, base: nil, index: nil,
                                    scale: 1, disp: disp, rip_relative: @mode == 64,
                                    seg: segment_for_mem)
          end

          if rm == 4
            sib = read_u8
            scale_bits = (sib >> 6) & 0x3
            index_bits = (sib >> 3) & 0x7
            base_bits  = sib & 0x7

            scale = 1 << scale_bits

            index = if index_bits == 4 && (@rex & REX_X) == 0
                      nil
                    else
                      index_bits | ((@rex & REX_X) != 0 ? 0x8 : 0)
                    end

            if base_bits == 5 && mod == 0
              base = nil
              disp = read_i32
            else
              base = base_bits | ((@rex & REX_B) != 0 ? 0x8 : 0)
              disp = case mod
                     when 0 then 0
                     when 1 then read_i8
                     when 2 then read_i32
                     end
            end

            return Operand::Mem.new(size: mem_size, base: base, index: index,
                                    scale: scale, disp: disp, rip_relative: false,
                                    seg: segment_for_mem)
          end

          base = rm | ((@rex & REX_B) != 0 ? 0x8 : 0)
          disp = case mod
                 when 0 then 0
                 when 1 then read_i8
                 when 2 then read_i32
                 end
          Operand::Mem.new(size: mem_size, base: base, index: nil, scale: 1,
                           disp: disp, rip_relative: false,
                           seg: segment_for_mem)
        end

        def segment_for_mem
          case @seg_override
          when :fs then :fs
          when :gs then :gs
          end
        end

        def build_reg(size, idx)
          # AH/CH/DH/BH only when 8-bit and NO REX prefix and idx in 4..7.
          # Normalize to base register index (0..3) and flag high_byte=true.
          if size == 8 && !@rex_present && idx >= 4 && idx <= 7
            Operand::Reg.new(size: 8, idx: idx - 4, high_byte: true)
          else
            Operand::Reg.new(size: size, idx: idx, high_byte: false)
          end
        end

        # ------------------------------------------------------------------
        # Operand sizing helpers
        # ------------------------------------------------------------------

        def operand_size_v
          if (@rex & REX_W) != 0
            64
          elsif @opsize_over
            16
          else
            32
          end
        end

        # "z" sized immediate per Intel: width-matched up to 32, then 32 (with
        # sign extension to 64 when REX.W). 8-bit ops use 8-bit immediates.
        def imm_size_z(size)
          case size
          when 8 then 8
          when 16 then 16
          else 32
          end
        end

        # ------------------------------------------------------------------
        # Immediates and relatives
        # ------------------------------------------------------------------

        def decode_imm(size, signed:)
          value = case size
                  when 8  then signed ? read_i8  : read_u8
                  when 16 then signed ? read_i16 : read_u16
                  when 32 then signed ? read_i32 : read_u32
                  when 64 then signed ? read_i64 : read_u64
                  end
          Operand::Imm.new(size: size, value: value, signed: signed)
        end

        def decode_rel(size)
          offset = case size
                   when 8  then read_i8
                   when 16 then read_i16
                   when 32 then read_i32
                   end
          Operand::Rel.new(size: size, offset: offset)
        end

        # ------------------------------------------------------------------
        # Byte stream helpers
        # ------------------------------------------------------------------

        def peek_u8
          @memory.read_u8(@cursor)
        end

        def consume_byte
          b = @memory.read_u8(@cursor)
          @raw << [b].pack("C")
          @cursor += 1
          b
        end

        def read_u8;  b = peek_u8; consume_byte; b; end

        def read_u16
          bytes = @memory.read(@cursor, 2)
          @cursor += 2
          @raw << bytes
          bytes.unpack1("v")
        end

        def read_u32
          bytes = @memory.read(@cursor, 4)
          @cursor += 4
          @raw << bytes
          bytes.unpack1("V")
        end

        def read_u64
          bytes = @memory.read(@cursor, 8)
          @cursor += 8
          @raw << bytes
          bytes.unpack1("Q<")
        end

        def read_i8
          v = read_u8
          v < 0x80 ? v : v - 0x100
        end

        def read_i16
          v = read_u16
          v < 0x8000 ? v : v - 0x1_0000
        end

        def read_i32
          v = read_u32
          v < 0x8000_0000 ? v : v - 0x1_0000_0000
        end

        def read_i64
          v = read_u64
          v < 0x8000_0000_0000_0000 ? v : v - 0x1_0000_0000_0000_0000
        end

        def instr(mnemonic, operands, **meta)
          Instruction.new(
            address: @address,
            mnemonic: mnemonic,
            operands: operands,
            length: @cursor - @address,
            meta: meta,
            raw: @raw.dup
          )
        end
      end
    end
  end
end
