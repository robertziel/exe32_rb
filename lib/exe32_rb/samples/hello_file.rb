# frozen_string_literal: true

module Exe32Rb
  module Samples
    # PE32 / i386 fixture that demonstrates host-backed file I/O: opens
    # `exe_rb_demo.txt` with CreateFileW, writes "Hello from exe_rb!\n"
    # with WriteFile, closes via CloseHandle, then ExitProcess.
    #
    # The runtime's kernel32 handlers back these APIs with real Ruby
    # File operations, so the file actually lands on disk in the
    # interpreter's current working directory.
    class HelloFile
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

      OUTPUT_PATH = "exe_rb_demo.txt"
      MESSAGE     = "Hello from exe_rb!\n"

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
        @rdata << ("\x00".b * 20)  # IAT: 4 entries + null

        @ilt_rva = rdata_cur_rva
        @rdata << ("\x00".b * 20)  # ILT: 4 entries + null

        @import_desc_rva = rdata_cur_rva
        @rdata << ("\x00".b * 40)  # 1 descriptor + null terminator

        @dll_name_rva = rdata_cur_rva
        @rdata << "kernel32.dll\x00".b
        pad_rdata_to(2)

        @hints = {}
        %w[CreateFileW WriteFile CloseHandle ExitProcess].each do |name|
          @hints[name] = rdata_cur_rva
          @rdata << [0].pack("v") + "#{name}\x00".b
          pad_rdata_to(2)
        end

        pad_rdata_to(2)
        @filename_rva = rdata_cur_rva
        OUTPUT_PATH.each_codepoint { |c| @rdata << [c].pack("v") }
        @rdata << "\x00\x00".b

        pad_rdata_to(4)
        @msg_rva = rdata_cur_rva
        @rdata << MESSAGE.b + "\x00".b

        fill_thunk_table(@iat_rva)
        fill_thunk_table(@ilt_rva)
        fill_import_descriptor
      end

      def fill_thunk_table(table_rva)
        off = table_rva - RDATA_RVA
        %w[CreateFileW WriteFile CloseHandle ExitProcess].each_with_index do |name, i|
          @rdata[off + i * 4, 4] = [@hints[name]].pack("V")
        end
      end

      def fill_import_descriptor
        off = @import_desc_rva - RDATA_RVA
        @rdata[off, 20] = [@ilt_rva, 0, 0, @dll_name_rva, @iat_rva].pack("V V V V V")
      end

      def layout_text
        @text = +"".b
        iat = ->(i) { IMAGE_BASE + @iat_rva + i * 4 }
        iat_create_file = iat[0]
        iat_write_file  = iat[1]
        iat_close       = iat[2]
        iat_exit        = iat[3]

        # CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)
        emit 0x6A, 0x00                                         # push 0  ; hTemplateFile
        emit 0x6A, 0x00                                         # push 0  ; dwFlagsAndAttributes
        emit 0x6A, 0x02                                         # push 2  ; CREATE_ALWAYS
        emit 0x6A, 0x00                                         # push 0  ; lpSecurityAttributes
        emit 0x6A, 0x00                                         # push 0  ; dwShareMode
        emit 0x68; emit_abs32(0x4000_0000)                      # push GENERIC_WRITE
        emit 0x68; emit_abs32(IMAGE_BASE + @filename_rva)       # push lpFileName
        emit 0xFF, 0x15; emit_abs32(iat_create_file)            # call [CreateFileW]

        # esi = handle
        emit 0x89, 0xC6                                         # mov esi, eax

        # WriteFile(esi, msg, msg_len, NULL, NULL)
        emit 0x6A, 0x00                                         # push 0  ; lpOverlapped
        emit 0x6A, 0x00                                         # push 0  ; lpNumberOfBytesWritten
        emit 0x6A, MESSAGE.bytesize & 0xFF                      # push 19 (message length)
        emit 0x68; emit_abs32(IMAGE_BASE + @msg_rva)            # push lpBuffer
        emit 0x56                                                # push esi (hFile)
        emit 0xFF, 0x15; emit_abs32(iat_write_file)             # call [WriteFile]

        # CloseHandle(esi)
        emit 0x56                                                # push esi
        emit 0xFF, 0x15; emit_abs32(iat_close)                  # call [CloseHandle]

        # ExitProcess(0)
        emit 0x6A, 0x00                                         # push 0
        emit 0xFF, 0x15; emit_abs32(iat_exit)                   # call [ExitProcess]

        emit 0xC3                                                # ret (unreachable)
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
        text_raw_size   = align_up(@text.bytesize, FILE_ALIGNMENT)
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

        bytes << [
          0x014C, 2, 0, 0, 0, 0x00E0, 0x0102
        ].pack("v v V V V v v")

        opt = +"".b
        opt << [0x10B].pack("v")
        opt << [1, 0].pack("C C")
        opt << [text_raw_size].pack("V")
        opt << [rdata_raw_size].pack("V")
        opt << [0].pack("V")
        opt << [TEXT_RVA].pack("V")
        opt << [TEXT_RVA].pack("V")
        opt << [RDATA_RVA].pack("V")
        opt << [IMAGE_BASE].pack("V")
        opt << [SECTION_ALIGNMENT].pack("V")
        opt << [FILE_ALIGNMENT].pack("V")
        opt << [4, 0].pack("v v")
        opt << [0, 0].pack("v v")
        opt << [4, 0].pack("v v")
        opt << [0].pack("V")
        opt << [size_of_image].pack("V")
        opt << [HEADER_SIZE].pack("V")
        opt << [0].pack("V")
        opt << [3].pack("v")
        opt << [0].pack("v")
        opt << [0x10_0000].pack("V")
        opt << [0x1000].pack("V")
        opt << [0x10_0000].pack("V")
        opt << [0x1000].pack("V")
        opt << [0].pack("V")
        opt << [16].pack("V")

        dirs = Array.new(16) { [0, 0] }
        dirs[1]  = [@import_desc_rva, 40]
        dirs[12] = [@iat_rva, 20]
        dirs.each { |va, sz| opt << [va, sz].pack("V V") }
        raise "optional header size #{opt.bytesize} != 0xE0" unless opt.bytesize == 0xE0

        bytes << opt

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
