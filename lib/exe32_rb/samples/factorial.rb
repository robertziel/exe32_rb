# frozen_string_literal: true

module Exe32Rb
  module Samples
    # Educational PE32 fixture demonstrating function calls, stack frames,
    # conditional branches, and IMUL — all classic teaching material.
    #
    # The binary computes factorial(5) recursively:
    #
    #     int factorial(int n) {
    #       if (n <= 1) return 1;
    #       return n * factorial(n - 1);
    #     }
    #     int main() {
    #       int r = factorial(5);
    #       /* print r as ASCII digit characters... */
    #       ExitProcess(r);   // -> 120 as exit code
    #     }
    #
    # Set a breakpoint on the recursive CALL (just past the prologue) and
    # step into see the stack frames grow:
    #
    #   $ exe32_rb debug examples/factorial.exe
    #   (exe32) b 0x401012   # the recursive call site
    #   (exe32) c            # break before the call
    #   (exe32) stack 6      # current frame
    #   (exe32) s            # step into factorial(4)
    #   (exe32) regs         # esp dropped 8 bytes; ebp not yet updated
    #
    # The exit_code is the answer (120 = 5! = 0x78).
    class Factorial
      IMAGE_BASE        = 0x0040_0000
      SECTION_ALIGNMENT = 0x1000
      FILE_ALIGNMENT    = 0x0200
      PE_OFFSET         = 0x40
      HEADER_SIZE       = 0x200
      TEXT_RVA          = 0x1000
      RDATA_RVA         = 0x2000

      SCN_CNT_CODE             = 0x0000_0020
      SCN_CNT_INITIALIZED_DATA = 0x0000_0040
      SCN_MEM_EXECUTE          = 0x2000_0000
      SCN_MEM_READ             = 0x4000_0000

      def self.write(path)
        File.binwrite(path, new.build)
        path
      end

      def build
        layout_rdata
        layout_text
        assemble
      end

      private

      def layout_rdata
        @rdata = +"".b
        @iat_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8) # 1 entry + null

        @ilt_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8)

        @import_desc_rva = rdata_cur_rva
        @rdata << ("\x00".b * 40)

        @dll_name_rva = rdata_cur_rva
        @rdata << "kernel32.dll\x00".b
        pad_rdata_to(2)

        @hint_exitprocess = rdata_cur_rva
        @rdata << [0].pack("v") + "ExitProcess\x00".b

        fill_thunk_table(@iat_rva)
        fill_thunk_table(@ilt_rva)
        fill_import_descriptor
      end

      def fill_thunk_table(table_rva)
        off = table_rva - RDATA_RVA
        @rdata[off, 4] = [@hint_exitprocess].pack("V")
      end

      def fill_import_descriptor
        off = @import_desc_rva - RDATA_RVA
        @rdata[off, 20] = [@ilt_rva, 0, 0, @dll_name_rva, @iat_rva].pack("V V V V V")
      end

      def layout_text
        @text = +"".b
        iat_exit = IMAGE_BASE + @iat_rva

        # ---- factorial(int n): arg lives at [ebp+8] in the new stack frame ----
        @factorial_addr = TEXT_RVA + @text.bytesize
        emit 0x55                          # push ebp
        emit 0x89, 0xE5                    # mov ebp, esp
        emit 0x8B, 0x45, 0x08              # mov eax, [ebp+8]   ; eax = n
        emit 0x83, 0xF8, 0x01              # cmp eax, 1
        # jle .base — patched once we know where .base is
        emit 0x7E, 0x00
        jle_fixup = @text.bytesize - 1     # offset of the rel8 byte
        # recursive case
        emit 0x48                          # dec eax            ; n-1
        emit 0x50                          # push eax           ; arg
        emit 0xE8                          # call factorial — rel32 patched below
        call_imm_off = @text.bytesize
        emit_imm32(0)
        next_after_call = TEXT_RVA + @text.bytesize
        rel = @factorial_addr - next_after_call
        @text[call_imm_off, 4] = [rel & 0xFFFF_FFFF].pack("V")
        emit 0x83, 0xC4, 0x04              # add esp, 4         ; cleanup arg
        emit 0x0F, 0xAF, 0x45, 0x08        # imul eax, [ebp+8]  ; eax *= n
        emit 0x5D                          # pop ebp
        emit 0xC3                          # ret
        # .base:
        base_addr = TEXT_RVA + @text.bytesize
        emit 0xB8, 0x01, 0x00, 0x00, 0x00  # mov eax, 1
        emit 0x5D                          # pop ebp
        emit 0xC3                          # ret

        # Patch the jle. Its rel8 is relative to the byte AFTER the rel8.
        jle_next_byte_rva = TEXT_RVA + jle_fixup + 1
        @text[jle_fixup, 1] = [(base_addr - jle_next_byte_rva) & 0xFF].pack("C")

        # ---- main / entry point ----
        @entry_addr = TEXT_RVA + @text.bytesize
        emit 0x6A, 0x05                    # push 5
        emit 0xE8                          # call factorial
        main_call_off = @text.bytesize
        emit_imm32(0)
        main_next = TEXT_RVA + @text.bytesize
        @text[main_call_off, 4] = [(@factorial_addr - main_next) & 0xFFFF_FFFF].pack("V")
        emit 0x83, 0xC4, 0x04              # add esp, 4
        emit 0x50                          # push eax (= 120)
        emit 0xFF, 0x15                    # call [iat_ExitProcess]
        emit_imm32(iat_exit)
        emit 0xC3                          # ret (unreachable)
      end

      def emit(*bytes)
        @text << bytes.pack("C*")
      end

      def emit_imm32(value)
        @text << [value & 0xFFFF_FFFF].pack("V")
      end

      def rdata_cur_rva
        RDATA_RVA + @rdata.bytesize
      end

      def pad_rdata_to(alignment)
        pad = (-@rdata.bytesize) % alignment
        @rdata << ("\x00".b * pad)
      end

      def assemble
        text_raw_size   = align_up(@text.bytesize,  FILE_ALIGNMENT)
        rdata_raw_size  = align_up(@rdata.bytesize, FILE_ALIGNMENT)
        text_raw_ptr    = HEADER_SIZE
        rdata_raw_ptr   = text_raw_ptr + text_raw_size
        text_virt_size  = @text.bytesize
        rdata_virt_size = @rdata.bytesize
        size_of_image   = align_up(RDATA_RVA + rdata_virt_size, SECTION_ALIGNMENT)

        bytes = +"".b
        dos = ("\x00".b * 64)
        dos[0, 2] = "MZ"
        dos[0x3C, 4] = [PE_OFFSET].pack("V")
        bytes << dos
        bytes << "PE\x00\x00".b
        bytes << [0x014C, 2, 0, 0, 0, 0x00E0, 0x0102].pack("v v V V V v v")

        opt = +"".b
        opt << [0x10B].pack("v")
        opt << [1, 0].pack("C C")
        opt << [text_raw_size].pack("V") << [rdata_raw_size].pack("V") << [0].pack("V")
        opt << [@entry_addr].pack("V") << [TEXT_RVA].pack("V") << [RDATA_RVA].pack("V")
        opt << [IMAGE_BASE].pack("V") << [SECTION_ALIGNMENT].pack("V") << [FILE_ALIGNMENT].pack("V")
        opt << [4, 0].pack("v v") << [0, 0].pack("v v") << [4, 0].pack("v v")
        opt << [0].pack("V") << [size_of_image].pack("V") << [HEADER_SIZE].pack("V") << [0].pack("V")
        opt << [3].pack("v") << [0].pack("v")
        opt << [0x10_0000].pack("V") << [0x1000].pack("V")
        opt << [0x10_0000].pack("V") << [0x1000].pack("V")
        opt << [0].pack("V") << [16].pack("V")
        dirs = Array.new(16) { [0, 0] }
        dirs[1]  = [@import_desc_rva, 40]
        dirs[12] = [@iat_rva, 8]
        dirs.each { |va, sz| opt << [va, sz].pack("V V") }
        raise "optional header size #{opt.bytesize} != 0xE0" unless opt.bytesize == 0xE0

        bytes << opt
        bytes << section_header(".text", text_virt_size, TEXT_RVA, text_raw_size, text_raw_ptr,
                                SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
        bytes << section_header(".rdata", rdata_virt_size, RDATA_RVA, rdata_raw_size, rdata_raw_ptr,
                                SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ)
        bytes << ("\x00".b * (HEADER_SIZE - bytes.bytesize))
        bytes << @text
        bytes << ("\x00".b * (text_raw_size - @text.bytesize))
        bytes << @rdata
        bytes << ("\x00".b * (rdata_raw_size - @rdata.bytesize))
        bytes
      end

      def section_header(name, vsize, vaddr, rsize, raddr, characteristics)
        hdr = +"".b
        hdr << name.b.ljust(8, "\x00")
        hdr << [vsize, vaddr, rsize, raddr].pack("V V V V")
        hdr << [0, 0].pack("V V") << [0, 0].pack("v v") << [characteristics].pack("V")
        hdr
      end

      def align_up(value, alignment)
        ((value + alignment - 1) / alignment) * alignment
      end
    end
  end
end
