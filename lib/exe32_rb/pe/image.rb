# frozen_string_literal: true

module Exe32Rb
  module PE
    # Parsed, in-memory representation of a PE32+ image.
    # Pure value types — no I/O.
    class Image
      Section = Struct.new(:name, :virtual_size, :virtual_address,
                           :size_of_raw_data, :pointer_to_raw_data,
                           :characteristics, :raw_data, keyword_init: true) do
        def contains_rva?(rva)
          size = [virtual_size, size_of_raw_data].max
          rva >= virtual_address && rva < virtual_address + size
        end

        def executable?
          (characteristics & Constants::SCN_MEM_EXECUTE) != 0
        end

        def writable?
          (characteristics & Constants::SCN_MEM_WRITE) != 0
        end

        def readable?
          (characteristics & Constants::SCN_MEM_READ) != 0
        end
      end

      DataDirectory = Struct.new(:virtual_address, :size, keyword_init: true) do
        def empty?
          virtual_address == 0 || size == 0
        end
      end

      Import = Struct.new(:dll, :name, :ordinal, :iat_rva, keyword_init: true) do
        def by_ordinal?
          !ordinal.nil?
        end

        def display_name
          by_ordinal? ? "#{dll}!##{ordinal}" : "#{dll}!#{name}"
        end
      end

      attr_reader :path, :machine, :bitness, :characteristics, :subsystem,
                  :image_base, :entry_point_rva, :size_of_image,
                  :size_of_headers, :section_alignment, :file_alignment,
                  :stack_reserve, :stack_commit, :heap_reserve, :heap_commit,
                  :sections, :data_directories, :imports, :resources

      def initialize(**attrs)
        @path              = attrs[:path]
        @machine           = attrs[:machine]
        @bitness           = attrs[:bitness]
        @characteristics   = attrs[:characteristics]
        @subsystem         = attrs[:subsystem]
        @image_base        = attrs[:image_base]
        @entry_point_rva   = attrs[:entry_point_rva]
        @size_of_image     = attrs[:size_of_image]
        @size_of_headers   = attrs[:size_of_headers]
        @section_alignment = attrs[:section_alignment]
        @file_alignment    = attrs[:file_alignment]
        @stack_reserve     = attrs[:stack_reserve]
        @stack_commit      = attrs[:stack_commit]
        @heap_reserve      = attrs[:heap_reserve]
        @heap_commit       = attrs[:heap_commit]
        @sections          = attrs[:sections]          || []
        @data_directories  = attrs[:data_directories]  || []
        @imports           = attrs[:imports]           || []
        @resources         = attrs[:resources]         || {}
      end

      def entry_point
        image_base + entry_point_rva
      end

      def section_by_rva(rva)
        sections.find { |s| s.contains_rva?(rva) }
      end

      def directory(index)
        data_directories[index]
      end

      # Look up a resource by (type, name[, language]). Each of type/name can be
      # either an integer ID (RT_RCDATA, MAKEINTRESOURCE) or a string (resource
      # name). Returns the leaf {data_rva:, size:, code_page:, entry_rva:} or nil.
      def find_resource(type, name, language = nil)
        type_branch = @resources[type] || @resources[type.is_a?(String) ? type.upcase : type]
        return nil unless type_branch.is_a?(Hash)

        name_branch = type_branch[name] || type_branch[name.is_a?(String) ? name.upcase : name]
        return nil unless name_branch.is_a?(Hash)

        if language && name_branch.key?(language)
          name_branch[language].is_a?(Hash) && name_branch[language].key?(:data_rva) ? name_branch[language] : nil
        else
          # Pick first language with a data leaf (recognizable by :data_rva)
          name_branch.each_value do |v|
            return v if v.is_a?(Hash) && v.key?(:data_rva)
          end
          nil
        end
      end
    end
  end
end
