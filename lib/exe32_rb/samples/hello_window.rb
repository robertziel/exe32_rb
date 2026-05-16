# frozen_string_literal: true

require_relative "hello_world"

module Exe32Rb
  module Samples
    # Tiny PE32 that creates a window through user32 instead of writing
    # to stdout. Imports:
    #
    #   user32!MessageBoxW           — opens a real window when run with --gui
    #   kernel32!ExitProcess         — clean exit
    #
    # Built the same way as HelloWorld (manual PE assembly) but with two
    # DLL imports + a UTF-16LE message string.
    class HelloWindow
      IMAGE_BASE        = 0x0040_0000
      SECTION_ALIGNMENT = 0x1000
      FILE_ALIGNMENT    = 0x0200
      PE_OFFSET         = 0x40
      HEADER_SIZE       = 0x400
      TEXT_RVA          = 0x1000
      RDATA_RVA         = 0x2000

      SCN_CNT_CODE             = 0x0000_0020
      SCN_CNT_INITIALIZED_DATA = 0x0000_0040
      SCN_MEM_EXECUTE          = 0x2000_0000
      SCN_MEM_READ             = 0x4000_0000

      TEXT    = "Hello from exe32_rb!"
      CAPTION = "exe32_rb GUI demo"

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

        # IAT entries for each import (pointed at by the IAT data dir).
        # Two DLLs, so two IATs back-to-back. The layout is:
        #   user32 IAT: [MessageBoxW, NULL]
        #   kernel32 IAT: [ExitProcess, NULL]
        @user32_iat_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8) # 1 entry + null
        @kernel32_iat_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8)

        # Identical ILTs.
        @user32_ilt_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8)
        @kernel32_ilt_rva = rdata_cur_rva
        @rdata << ("\x00".b * 8)

        # Import descriptor table: 2 descriptors + null terminator.
        @import_desc_rva = rdata_cur_rva
        @rdata << ("\x00".b * 60) # 20*2 + 20 null

        # DLL names
        @user32_name_rva = rdata_cur_rva
        @rdata << "user32.dll\x00".b
        pad_rdata_to(2)
        @kernel32_name_rva = rdata_cur_rva
        @rdata << "kernel32.dll\x00".b
        pad_rdata_to(2)

        # Hint/Name entries — { word hint=0; char name[]; }
        @hint_messageboxw = rdata_cur_rva
        @rdata << [0].pack("v") + "MessageBoxW\x00".b
        pad_rdata_to(2)

        @hint_exitprocess = rdata_cur_rva
        @rdata << [0].pack("v") + "ExitProcess\x00".b
        pad_rdata_to(8)

        # The text + caption as UTF-16LE strings.
        @text_rva = rdata_cur_rva
        TEXT.each_codepoint { |cp| @rdata << [cp & 0xFFFF].pack("v") }
        @rdata << "\x00\x00".b
        pad_rdata_to(2)

        @caption_rva = rdata_cur_rva
        CAPTION.each_codepoint { |cp| @rdata << [cp & 0xFFFF].pack("v") }
        @rdata << "\x00\x00".b
        pad_rdata_to(8)

        # Fill the thunks (each thunk = RVA of the hint/name entry).
        write_u32(@user32_iat_rva,    @hint_messageboxw)
        write_u32(@user32_iat_rva + 4, 0)
        write_u32(@kernel32_iat_rva,    @hint_exitprocess)
        write_u32(@kernel32_iat_rva + 4, 0)
        write_u32(@user32_ilt_rva,    @hint_messageboxw)
        write_u32(@user32_ilt_rva + 4, 0)
        write_u32(@kernel32_ilt_rva,    @hint_exitprocess)
        write_u32(@kernel32_ilt_rva + 4, 0)

        # Import descriptors: { OriginalFirstThunk(ILT), TimeDateStamp,
        # ForwarderChain, Name, FirstThunk(IAT) }.
        write_u32(@import_desc_rva +  0, @user32_ilt_rva)
        write_u32(@import_desc_rva + 12, @user32_name_rva)
        write_u32(@import_desc_rva + 16, @user32_iat_rva)
        write_u32(@import_desc_rva + 20, @kernel32_ilt_rva)
        write_u32(@import_desc_rva + 32, @kernel32_name_rva)
        write_u32(@import_desc_rva + 36, @kernel32_iat_rva)
      end

      def layout_text
        @text = +"".b
        iat_mb     = IMAGE_BASE + @user32_iat_rva
        iat_exit   = IMAGE_BASE + @kernel32_iat_rva
        text_va    = IMAGE_BASE + @text_rva
        caption_va = IMAGE_BASE + @caption_rva

        # MessageBoxW(hWnd=0, lpText, lpCaption, uType=MB_OK=0)
        emit 0x6A, 0x00                       # push 0  (uType)
        emit 0x68; emit_abs32(caption_va)     # push lpCaption
        emit 0x68; emit_abs32(text_va)        # push lpText
        emit 0x6A, 0x00                       # push 0  (hWnd)
        emit 0xFF, 0x15; emit_abs32(iat_mb)   # call [MessageBoxW]

        # ExitProcess(0)
        emit 0x6A, 0x00
        emit 0xFF, 0x15; emit_abs32(iat_exit)

        # safety RET
        emit 0xC3
      end

      def emit(*bytes)
        @text << bytes.pack("C*")
      end

      def emit_abs32(value)
        @text << [value].pack("V")
      end

      def write_u32(rva, value)
        off = rva - RDATA_RVA
        @rdata[off, 4] = [value].pack("V")
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
        bytes << [
          0x014C, 2, 0, 0, 0, 0x00E0, 0x0102,
        ].pack("v v V V V v v")

        opt = +"".b
        opt << [0x10B].pack("v") << [1, 0].pack("C C")
        opt << [text_raw_size].pack("V") << [rdata_raw_size].pack("V") << [0].pack("V")
        opt << [TEXT_RVA].pack("V") << [TEXT_RVA].pack("V")
        opt << [RDATA_RVA].pack("V")
        opt << [IMAGE_BASE].pack("V")
        opt << [SECTION_ALIGNMENT].pack("V") << [FILE_ALIGNMENT].pack("V")
        opt << [4, 0].pack("v v") << [0, 0].pack("v v") << [4, 0].pack("v v")
        opt << [0].pack("V") << [size_of_image].pack("V") << [HEADER_SIZE].pack("V") << [0].pack("V")
        opt << [2].pack("v") << [0].pack("v")  # Subsystem = WINDOWS_GUI
        opt << [0x10_0000].pack("V") << [0x1000].pack("V")
        opt << [0x10_0000].pack("V") << [0x1000].pack("V")
        opt << [0].pack("V") << [16].pack("V")

        dirs = Array.new(16) { [0, 0] }
        dirs[1]  = [@import_desc_rva, 40]
        dirs[12] = [@user32_iat_rva, 16] # IAT directory covers both adjacent IATs
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
        hdr << [0, 0].pack("V V") << [0, 0].pack("v v")
        hdr << [characteristics].pack("V")
        hdr
      end

      def align_up(value, alignment)
        ((value + alignment - 1) / alignment) * alignment
      end
    end
  end
end
