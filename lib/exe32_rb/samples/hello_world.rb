# frozen_string_literal: true

module Exe32Rb
  module Samples
    # Builds a minimal valid 32-bit Windows PE (PE32 / i386) that calls
    # kernel32 GetStdHandle / WriteFile / ExitProcess via __stdcall and
    # prints "Hello, world!" before exiting.
    #
    # Layout matches HelloWorld but with 32-bit thunks, a smaller optional
    # header (0xE0 bytes), and i386 instructions with absolute disp32
    # operands (no RIP-relative).
    class HelloWorld
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

      MESSAGE = "Hello, world!\n"

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
        @rdata << ("\x00".b * 16)   # IAT: 3 entries (4B each) + null term

        @ilt_rva = rdata_cur_rva
        @rdata << ("\x00".b * 16)   # ILT: same

        @import_desc_rva = rdata_cur_rva
        @rdata << ("\x00".b * 40)   # 1 descriptor (20B) + null term (20B)

        @dll_name_rva = rdata_cur_rva
        @rdata << "kernel32.dll\x00".b
        pad_rdata_to(2)

        @hint_getstdhandle = rdata_cur_rva
        @rdata << [0].pack("v") + "GetStdHandle\x00".b
        pad_rdata_to(2)

        @hint_writefile = rdata_cur_rva
        @rdata << [0].pack("v") + "WriteFile\x00".b
        pad_rdata_to(2)

        @hint_exitprocess = rdata_cur_rva
        @rdata << [0].pack("v") + "ExitProcess\x00".b
        pad_rdata_to(8)

        @msg_rva = rdata_cur_rva
        @rdata << MESSAGE.b + "\x00".b

        fill_thunk_table(@iat_rva)
        fill_thunk_table(@ilt_rva)
        fill_import_descriptor
      end

      def fill_thunk_table(table_rva)
        off = table_rva - RDATA_RVA
        [@hint_getstdhandle, @hint_writefile, @hint_exitprocess].each_with_index do |hint, i|
          @rdata[off + i * 4, 4] = [hint].pack("V")
        end
      end

      def fill_import_descriptor
        off = @import_desc_rva - RDATA_RVA
        @rdata[off, 20] = [@ilt_rva, 0, 0, @dll_name_rva, @iat_rva].pack("V V V V V")
      end

      def layout_text
        @text = +"".b
        iat_get  = IMAGE_BASE + @iat_rva
        iat_wf   = IMAGE_BASE + @iat_rva + 4
        iat_exit = IMAGE_BASE + @iat_rva + 8
        msg_va   = IMAGE_BASE + @msg_rva

        # push -11                        ; STD_OUTPUT_HANDLE
        emit 0x6A, 0xF5

        # call dword ptr [iat_get_stdhandle]
        emit 0xFF, 0x15; emit_abs32(iat_get)

        # WriteFile args pushed right-to-left:
        # push 0  (lpOverlapped)
        emit 0x6A, 0x00
        # push 0  (lpNumberOfBytesWritten)
        emit 0x6A, 0x00
        # push MESSAGE.bytesize  (nNumberOfBytesToWrite)
        emit 0x6A, MESSAGE.bytesize & 0xFF
        # push msg  (lpBuffer)
        emit 0x68; emit_abs32(msg_va)
        # push eax  (hFile from GetStdHandle)
        emit 0x50

        # call dword ptr [iat_writefile]
        emit 0xFF, 0x15; emit_abs32(iat_wf)

        # push 0  (exit code)
        emit 0x6A, 0x00
        # call dword ptr [iat_exitprocess]
        emit 0xFF, 0x15; emit_abs32(iat_exit)

        # ret (unreachable)
        emit 0xC3
      end

      def emit(*bytes)
        @text << bytes.pack("C*")
      end

      def emit_abs32(value)
        @text << [value].pack("V")
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

        # DOS header
        dos = ("\x00".b * 64)
        dos[0, 2] = "MZ"
        dos[0x3C, 4] = [PE_OFFSET].pack("V")
        bytes << dos

        # PE signature
        bytes << "PE\x00\x00".b

        # COFF header
        bytes << [
          0x014C,        # Machine = I386
          2,             # NumberOfSections
          0,             # TimeDateStamp
          0,             # PointerToSymbolTable
          0,             # NumberOfSymbols
          0x00E0,        # SizeOfOptionalHeader = 224 (PE32)
          0x0102,        # EXECUTABLE_IMAGE | 32BIT_MACHINE
        ].pack("v v V V V v v")

        # Optional Header (PE32, 0xE0 bytes total)
        opt = +"".b
        opt << [0x10B].pack("v")         # Magic = PE32
        opt << [1, 0].pack("C C")
        opt << [text_raw_size].pack("V")
        opt << [rdata_raw_size].pack("V")
        opt << [0].pack("V")
        opt << [TEXT_RVA].pack("V")
        opt << [TEXT_RVA].pack("V")
        opt << [RDATA_RVA].pack("V")     # BaseOfData (PE32-only)
        opt << [IMAGE_BASE].pack("V")    # 32-bit ImageBase
        opt << [SECTION_ALIGNMENT].pack("V")
        opt << [FILE_ALIGNMENT].pack("V")
        opt << [4, 0].pack("v v")        # OS version
        opt << [0, 0].pack("v v")        # image version
        opt << [4, 0].pack("v v")        # subsystem version
        opt << [0].pack("V")             # Win32VersionValue
        opt << [size_of_image].pack("V")
        opt << [HEADER_SIZE].pack("V")
        opt << [0].pack("V")             # CheckSum
        opt << [3].pack("v")             # Subsystem CUI
        opt << [0].pack("v")             # DllCharacteristics
        opt << [0x10_0000].pack("V")     # 32-bit StackReserve
        opt << [0x1000].pack("V")        # StackCommit
        opt << [0x10_0000].pack("V")     # HeapReserve
        opt << [0x1000].pack("V")        # HeapCommit
        opt << [0].pack("V")             # LoaderFlags
        opt << [16].pack("V")            # NumberOfRvaAndSizes

        dirs = Array.new(16) { [0, 0] }
        dirs[1]  = [@import_desc_rva, 40]
        dirs[12] = [@iat_rva, 16]
        dirs.each { |va, sz| opt << [va, sz].pack("V V") }
        raise "optional header size #{opt.bytesize} != 0xE0" unless opt.bytesize == 0xE0

        bytes << opt

        # Section headers
        bytes << section_header(".text",
                                 virtual_size: text_virt_size,
                                 virtual_address: TEXT_RVA,
                                 size_of_raw_data: text_raw_size,
                                 pointer_to_raw_data: text_raw_ptr,
                                 characteristics: SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
        bytes << section_header(".rdata",
                                 virtual_size: rdata_virt_size,
                                 virtual_address: RDATA_RVA,
                                 size_of_raw_data: rdata_raw_size,
                                 pointer_to_raw_data: rdata_raw_ptr,
                                 characteristics: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ)

        bytes << ("\x00".b * (HEADER_SIZE - bytes.bytesize))

        bytes << @text
        bytes << ("\x00".b * (text_raw_size - @text.bytesize))

        bytes << @rdata
        bytes << ("\x00".b * (rdata_raw_size - @rdata.bytesize))

        bytes
      end

      def section_header(name, virtual_size:, virtual_address:, size_of_raw_data:, pointer_to_raw_data:, characteristics:)
        hdr = +"".b
        hdr << name.b.ljust(8, "\x00")
        hdr << [virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data].pack("V V V V")
        hdr << [0, 0].pack("V V")
        hdr << [0, 0].pack("v v")
        hdr << [characteristics].pack("V")
        hdr
      end

      def align_up(value, alignment)
        ((value + alignment - 1) / alignment) * alignment
      end
    end
  end
end
