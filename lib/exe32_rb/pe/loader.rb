# frozen_string_literal: true

module Exe32Rb
  module PE
    # Reads a PE32+ executable from disk and parses it into an Image.
    class Loader
      include Constants

      DOS_HEADER_SIZE          = 64
      DOS_E_LFANEW_OFFSET      = 0x3C
      COFF_HEADER_SIZE         = 20
      SECTION_HEADER_SIZE      = 40
      DATA_DIRECTORY_ENTRIES   = 16
      OPTIONAL_HEADER_FIXED_SZ = 112 # PE32+ fixed part, before data directories

      def self.load(path)
        new(path).load
      end

      def initialize(path)
        @path  = path
        @data  = File.binread(path)
        @cur   = 0
      end

      def load
        parse_dos_header
        seek(@pe_offset)
        parse_pe_signature
        parse_coff_header
        parse_optional_header
        parse_section_headers
        attach_raw_data
        imports = parse_imports
        resources = parse_resources

        Image.new(
          path: @path,
          machine: @machine,
          bitness: @bitness,
          characteristics: @characteristics,
          subsystem: @subsystem,
          image_base: @image_base,
          entry_point_rva: @entry_point_rva,
          size_of_image: @size_of_image,
          size_of_headers: @size_of_headers,
          section_alignment: @section_alignment,
          file_alignment: @file_alignment,
          stack_reserve: @stack_reserve,
          stack_commit: @stack_commit,
          heap_reserve: @heap_reserve,
          heap_commit: @heap_commit,
          sections: @sections,
          data_directories: @data_directories,
          imports: imports,
          resources: resources
        )
      end

      private

      def parse_dos_header
        raise Exe32Rb::LoadError, "file too small for DOS header" if @data.bytesize < DOS_HEADER_SIZE

        sig = u16_at(0)
        raise Exe32Rb::LoadError, format("not a PE: missing MZ (got 0x%04X)", sig) unless sig == DOS_SIGNATURE

        @pe_offset = u32_at(DOS_E_LFANEW_OFFSET)
      end

      def parse_pe_signature
        sig = read_u32
        raise Exe32Rb::LoadError, format("not a PE: missing PE\\0\\0 (got 0x%08X)", sig) unless sig == PE_SIGNATURE
      end

      def parse_coff_header
        @machine                  = read_u16
        @number_of_sections       = read_u16
        @time_date_stamp          = read_u32
        @pointer_to_symbol_table  = read_u32
        @number_of_symbols        = read_u32
        @size_of_optional_header  = read_u16
        @characteristics          = read_u16
      end

      # Branches by Optional Header magic word: PE32 vs PE32+ differ in
      # where the image base, stack/heap sizes, and BaseOfData live.
      def parse_optional_header
        magic = read_u16
        case magic
        when OPTIONAL_MAGIC_PE32  then parse_pe32_optional_header
        when OPTIONAL_MAGIC_PE32P then parse_pe32p_optional_header
        else
          raise Exe32Rb::LoadError, format("unknown optional header magic 0x%04X", magic)
        end
      end

      def parse_pe32_optional_header
        @bitness = 32
        read_u8 # MajorLinkerVersion
        read_u8 # MinorLinkerVersion
        @size_of_code                  = read_u32
        @size_of_initialized_data      = read_u32
        @size_of_uninitialized_data    = read_u32
        @entry_point_rva               = read_u32
        @base_of_code                  = read_u32
        read_u32                        # BaseOfData (PE32 only)
        @image_base                    = read_u32
        @section_alignment             = read_u32
        @file_alignment                = read_u32
        6.times { read_u16 }            # OS/Image/Subsystem version pairs
        read_u32                        # Win32VersionValue
        @size_of_image                 = read_u32
        @size_of_headers               = read_u32
        read_u32                        # CheckSum
        @subsystem                     = read_u16
        read_u16                        # DllCharacteristics
        @stack_reserve                 = read_u32
        @stack_commit                  = read_u32
        @heap_reserve                  = read_u32
        @heap_commit                   = read_u32
        read_u32                        # LoaderFlags
        number_of_rva_and_sizes        = read_u32

        parse_data_directories(number_of_rva_and_sizes)
      end

      def parse_pe32p_optional_header
        @bitness = 64
        read_u8                         # MajorLinkerVersion
        read_u8                         # MinorLinkerVersion
        @size_of_code                  = read_u32
        @size_of_initialized_data      = read_u32
        @size_of_uninitialized_data    = read_u32
        @entry_point_rva               = read_u32
        @base_of_code                  = read_u32
        @image_base                    = read_u64
        @section_alignment             = read_u32
        @file_alignment                = read_u32
        6.times { read_u16 }
        read_u32                        # Win32VersionValue
        @size_of_image                 = read_u32
        @size_of_headers               = read_u32
        read_u32                        # CheckSum
        @subsystem                     = read_u16
        read_u16                        # DllCharacteristics
        @stack_reserve                 = read_u64
        @stack_commit                  = read_u64
        @heap_reserve                  = read_u64
        @heap_commit                   = read_u64
        read_u32                        # LoaderFlags
        number_of_rva_and_sizes        = read_u32

        parse_data_directories(number_of_rva_and_sizes)
      end

      def parse_data_directories(count)
        @data_directories = Array.new(DATA_DIRECTORY_ENTRIES) do |i|
          if i < count
            Image::DataDirectory.new(virtual_address: read_u32, size: read_u32)
          else
            Image::DataDirectory.new(virtual_address: 0, size: 0)
          end
        end
      end

      def parse_section_headers
        @sections = Array.new(@number_of_sections) do
          name_raw = read_bytes(8)
          name = name_raw.unpack1("Z8")

          virtual_size         = read_u32
          virtual_address      = read_u32
          size_of_raw_data     = read_u32
          pointer_to_raw_data  = read_u32
          read_u32             # PointerToRelocations
          read_u32             # PointerToLinenumbers
          read_u16             # NumberOfRelocations
          read_u16             # NumberOfLinenumbers
          characteristics      = read_u32

          Image::Section.new(
            name: name,
            virtual_size: virtual_size,
            virtual_address: virtual_address,
            size_of_raw_data: size_of_raw_data,
            pointer_to_raw_data: pointer_to_raw_data,
            characteristics: characteristics
          )
        end
      end

      def attach_raw_data
        @sections.each do |s|
          if s.size_of_raw_data > 0 && s.pointer_to_raw_data > 0
            s.raw_data = @data.byteslice(s.pointer_to_raw_data, s.size_of_raw_data) || ""
          else
            s.raw_data = ""
          end
        end
      end

      def parse_imports
        dir = @data_directories[Constants::DIR_IMPORT]
        return [] if dir.nil? || dir.empty?

        thunk_size, ordinal_flag = if @bitness == 64
                                     [8, IMPORT_ORDINAL_FLAG64]
                                   else
                                     [4, 1 << 31]
                                   end

        imports = []
        idx = dir.virtual_address
        loop do
          ilt_rva     = read_u32_rva(idx)
          read_u32_rva(idx + 4)  # TimeDateStamp
          read_u32_rva(idx + 8)  # ForwarderChain
          name_rva    = read_u32_rva(idx + 12)
          iat_rva     = read_u32_rva(idx + 16)
          idx += 20

          break if ilt_rva == 0 && name_rva == 0 && iat_rva == 0

          dll_name = read_cstring_at_rva(name_rva)
          thunk_table_rva = ilt_rva != 0 ? ilt_rva : iat_rva
          slot = 0
          loop do
            entry = read_thunk(thunk_table_rva + slot * thunk_size)
            break if entry == 0

            iat_slot_rva = iat_rva + slot * thunk_size
            if (entry & ordinal_flag) != 0
              imports << Image::Import.new(
                dll: dll_name, name: nil, ordinal: entry & 0xFFFF,
                iat_rva: iat_slot_rva
              )
            else
              hint_name_rva = entry & 0x7FFF_FFFF
              name = read_cstring_at_rva(hint_name_rva + 2)
              imports << Image::Import.new(
                dll: dll_name, name: name, ordinal: nil,
                iat_rva: iat_slot_rva
              )
            end
            slot += 1
          end
        end
        imports
      end

      # Parse the IMAGE_RESOURCE_DIRECTORY tree into a nested Hash:
      #   { type_id_or_name => { name_id_or_name => { lang_id => entry } } }
      # where entry = {data_rva:, size:, code_page:, entry_rva:}.
      # The high bit of an entry's Name field distinguishes string-name (1) vs
      # integer-id (0). The high bit of OffsetToData distinguishes subdirectory
      # vs data leaf.
      def parse_resources
        dir = @data_directories[Constants::DIR_RESOURCE]
        return {} if dir.nil? || dir.empty?

        @rsrc_base_rva = dir.virtual_address
        walk_resource_directory(@rsrc_base_rva)
      end

      def walk_resource_directory(dir_rva)
        num_named = read_u16_rva(dir_rva + 12)
        num_id    = read_u16_rva(dir_rva + 14)
        result = {}
        (num_named + num_id).times do |i|
          entry_rva = dir_rva + 16 + i * 8
          name_field = read_u32_rva(entry_rva)
          data_field = read_u32_rva(entry_rva + 4)

          name = if (name_field & 0x8000_0000) != 0
                   read_resource_string_at(@rsrc_base_rva + (name_field & 0x7FFF_FFFF))
                 else
                   name_field & 0xFFFF
                 end

          if (data_field & 0x8000_0000) != 0
            result[name] = walk_resource_directory(@rsrc_base_rva + (data_field & 0x7FFF_FFFF))
          else
            data_entry_rva = @rsrc_base_rva + (data_field & 0x7FFF_FFFF)
            result[name] = {
              data_rva:   read_u32_rva(data_entry_rva),
              size:       read_u32_rva(data_entry_rva + 4),
              code_page:  read_u32_rva(data_entry_rva + 8),
              entry_rva:  data_entry_rva,
            }
          end
        end
        result
      end

      def read_resource_string_at(rva)
        offset = rva_to_file_offset(rva)
        length = u16_at(offset)
        bytes  = @data.byteslice(offset + 2, length * 2)
        bytes.force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8)
      end

      def read_thunk(rva)
        @bitness == 64 ? read_u64_rva(rva) : read_u32_rva(rva)
      end

      # --- byte reading helpers ------------------------------------------------

      def seek(offset)
        @cur = offset
      end

      def read_bytes(n)
        bytes = @data.byteslice(@cur, n) or raise Exe32Rb::LoadError, "read past EOF at #{@cur}"
        raise Exe32Rb::LoadError, "short read at #{@cur}" if bytes.bytesize < n

        @cur += n
        bytes
      end

      def read_u8;  read_bytes(1).unpack1("C");  end
      def read_u16; read_bytes(2).unpack1("v");  end
      def read_u32; read_bytes(4).unpack1("V");  end
      def read_u64; read_bytes(8).unpack1("Q<"); end

      def u16_at(off); @data.byteslice(off, 2).unpack1("v");  end
      def u32_at(off); @data.byteslice(off, 4).unpack1("V");  end

      # RVA reads go through section table → file offset
      def rva_to_file_offset(rva)
        section = @sections.find { |s| s.contains_rva?(rva) }
        raise Exe32Rb::LoadError, format("RVA 0x%X is not in any section", rva) unless section

        section.pointer_to_raw_data + (rva - section.virtual_address)
      end

      def read_u16_rva(rva); u16_at(rva_to_file_offset(rva)); end
      def read_u32_rva(rva); u32_at(rva_to_file_offset(rva)); end

      def read_u64_rva(rva)
        @data.byteslice(rva_to_file_offset(rva), 8).unpack1("Q<")
      end

      def read_cstring_at_rva(rva)
        off = rva_to_file_offset(rva)
        terminator = @data.index("\x00", off) || @data.bytesize
        @data.byteslice(off, terminator - off)
      end
    end
  end
end
