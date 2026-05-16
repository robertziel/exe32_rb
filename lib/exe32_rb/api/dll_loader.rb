# frozen_string_literal: true

module Exe32Rb
  module Api
    # Real DLL loader: maps secondary PE files into the emulator's
    # virtual memory, parses their export table, and surfaces named
    # exports via GetProcAddress.
    #
    # Limitations of this minimal implementation:
    #   - We don't run DllMain (so DLLs that need init don't fully work).
    #   - We don't process the DLL's own imports recursively. If a loaded
    #     DLL imports from another DLL we haven't loaded, those imports
    #     resolve to 0; calling them would crash.
    #   - We don't process base relocations. The DLL must be loadable at
    #     its preferred ImageBase or use position-independent code.
    #   - Forwarded exports aren't followed.
    #
    # Use case: making LoadLibraryA/W return a real handle that
    # GetProcAddress can resolve actual exports from. Sufficient for
    # binaries that load a DLL just to peek at its constants or version
    # info, but not for full game-engine DLL invocation.
    class DllLoader
      MAX_HANDLES = 16

      Module = Struct.new(:name, :base, :size, :exports, keyword_init: true)

      def initialize(machine)
        @machine  = machine
        @modules  = {}  # module_handle => Module
        @by_name  = {}  # downcase name => module_handle
        @next_base = 0x10_000_000  # synthetic load addresses for DLLs
      end

      attr_reader :modules

      # Load a DLL from disk. Returns the module handle (its load
      # address), or 0 on failure.
      def load(name, dll_search_paths: [])
        downcased = name.downcase
        return @by_name[downcased] if @by_name[downcased]

        path = resolve(name, dll_search_paths)
        return 0 unless path

        data  = File.binread(path)
        image = parse_pe_for_loading(data)
        return 0 unless image

        size = align_up(image[:size_of_image], 0x1000)
        base = @next_base
        @next_base += align_up(size, 0x1_000_000) # space DLLs 16MB apart

        @machine.memory.map(base, size, permissions: Emulator::Memory::PERM_RWX,
                            name: "dll:#{name}")
        # Map header bytes
        @machine.memory.write(base, data.byteslice(0, image[:size_of_headers]))
        image[:sections].each do |s|
          raw = data.byteslice(s[:pointer_to_raw_data], s[:size_of_raw_data]) || ""
          @machine.memory.write(base + s[:virtual_address], raw) unless raw.empty?
        end

        exports = parse_exports(data, image)
        mod = Module.new(name: name, base: base, size: size, exports: exports)
        @modules[base] = mod
        @by_name[downcased] = base
        warn format("[dll] loaded %s @ 0x%08X (%d exports)", name, base, exports.size)
        base
      end

      def get_proc_address(handle, name)
        mod = @modules[handle]
        return 0 unless mod
        return 0 unless (rva = mod.exports[name])

        mod.base + rva
      end

      private

      def resolve(name, search_paths)
        candidates = search_paths + [Dir.pwd, "/tmp", "."]
        candidates.each do |dir|
          [name, "#{name}.dll"].each do |fname|
            full = File.expand_path(fname, dir)
            return full if File.file?(full)
          end
        end
        nil
      end

      def parse_pe_for_loading(data)
        return nil if data.bytesize < 64
        return nil unless data.byteslice(0, 2) == "MZ"

        pe_off = data.byteslice(0x3C, 4).unpack1("V")
        return nil unless data.byteslice(pe_off, 4) == "PE\x00\x00"

        coff_off = pe_off + 4
        machine_w        = data.byteslice(coff_off + 0, 2).unpack1("v")
        num_sections     = data.byteslice(coff_off + 2, 2).unpack1("v")
        size_of_opt      = data.byteslice(coff_off + 16, 2).unpack1("v")
        opt_off = coff_off + 20

        magic = data.byteslice(opt_off, 2).unpack1("v")
        is_pe32p = (magic == 0x20B)

        # We only support i386 DLLs for the i386 emulator
        return nil if machine_w != 0x014C # MACHINE_I386

        size_of_image = data.byteslice(opt_off + 56, 4).unpack1("V")
        size_of_headers = data.byteslice(opt_off + 60, 4).unpack1("V")
        export_dir_off = is_pe32p ? opt_off + 112 : opt_off + 96
        export_rva   = data.byteslice(export_dir_off + 0, 4).unpack1("V")
        export_size  = data.byteslice(export_dir_off + 4, 4).unpack1("V")

        sections = []
        sec_off = opt_off + size_of_opt
        num_sections.times do |i|
          base_off = sec_off + i * 40
          sections << {
            name:                data.byteslice(base_off, 8).unpack1("Z8"),
            virtual_size:        data.byteslice(base_off + 8, 4).unpack1("V"),
            virtual_address:     data.byteslice(base_off + 12, 4).unpack1("V"),
            size_of_raw_data:    data.byteslice(base_off + 16, 4).unpack1("V"),
            pointer_to_raw_data: data.byteslice(base_off + 20, 4).unpack1("V"),
          }
        end

        {
          size_of_image: size_of_image,
          size_of_headers: size_of_headers,
          sections: sections,
          export_rva: export_rva,
          export_size: export_size,
        }
      end

      def parse_exports(data, image)
        return {} if image[:export_rva] == 0 || image[:export_size] == 0

        # Convert RVA to file offset for the export directory itself
        sec = image[:sections].find { |s| image[:export_rva] >= s[:virtual_address] && image[:export_rva] < s[:virtual_address] + [s[:virtual_size], s[:size_of_raw_data]].max }
        return {} unless sec

        ed = image[:export_rva] - sec[:virtual_address] + sec[:pointer_to_raw_data]
        n_names         = data.byteslice(ed + 24, 4).unpack1("V")
        addr_funcs      = data.byteslice(ed + 28, 4).unpack1("V")
        addr_names      = data.byteslice(ed + 32, 4).unpack1("V")
        addr_name_ords  = data.byteslice(ed + 36, 4).unpack1("V")

        result = {}
        n_names.times do |i|
          name_rva = data.byteslice(rva_to_off(image, addr_names + i * 4), 4).unpack1("V")
          name_off = rva_to_off(image, name_rva)
          name_end = data.index("\x00", name_off) || name_off
          name = data.byteslice(name_off, name_end - name_off)

          ordinal = data.byteslice(rva_to_off(image, addr_name_ords + i * 2), 2).unpack1("v")
          fn_rva  = data.byteslice(rva_to_off(image, addr_funcs + ordinal * 4), 4).unpack1("V")
          result[name] = fn_rva
        end
        result
      end

      def rva_to_off(image, rva)
        sec = image[:sections].find { |s| rva >= s[:virtual_address] && rva < s[:virtual_address] + [s[:virtual_size], s[:size_of_raw_data]].max }
        sec[:pointer_to_raw_data] + (rva - sec[:virtual_address])
      end

      def align_up(value, alignment)
        ((value + alignment - 1) / alignment) * alignment
      end
    end

    # Module-level convenience: install LoadLibraryA/W and GetProcAddress
    # handlers backed by a shared DllLoader instance.
    module DllLoaderInstall
      def self.install(machine, search_paths: [])
        loader = DllLoader.new(machine)
        machine.singleton_class.attr_accessor :dll_loader
        machine.dll_loader = loader

        dispatcher = machine.dispatcher
        dispatcher.install_handler("kernel32.dll", "LoadLibraryA", args: 1) do |mach, args|
          loader.load(mach.read_cstring(args[0]), dll_search_paths: search_paths)
        end
        dispatcher.install_handler("kernel32.dll", "LoadLibraryW", args: 1) do |mach, args|
          loader.load(mach.read_wstring(args[0]), dll_search_paths: search_paths)
        end
        dispatcher.install_handler("kernel32.dll", "LoadLibraryExA", args: 3) do |mach, args|
          loader.load(mach.read_cstring(args[0]), dll_search_paths: search_paths)
        end
        dispatcher.install_handler("kernel32.dll", "LoadLibraryExW", args: 3) do |mach, args|
          loader.load(mach.read_wstring(args[0]), dll_search_paths: search_paths)
        end
        dispatcher.install_handler("kernel32.dll", "FreeLibrary", args: 1) { 1 }
        dispatcher.install_handler("kernel32.dll", "GetProcAddress", args: 2) do |mach, args|
          handle = args[0] & 0xFFFF_FFFF
          name_ptr = args[1] & 0xFFFF_FFFF
          # name_ptr can be either a string pointer or a low-16-bit ordinal
          if (name_ptr & 0xFFFF_0000) == 0
            0 # ordinal lookups not supported
          else
            loader.get_proc_address(handle, mach.read_cstring(name_ptr))
          end
        end
      end
    end
  end
end
