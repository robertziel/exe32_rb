# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Sparse paged 64-bit virtual address space.
    #
    # Pages are 4 KiB. Mapped pages live in @pages keyed by page number.
    # Permissions are tracked per page but not strictly enforced — we record
    # them so a future strict mode can refuse the wrong kind of access.
    class Memory
      PAGE_BITS = 12
      PAGE_SIZE = 1 << PAGE_BITS
      PAGE_MASK = PAGE_SIZE - 1

      PERM_R = 1
      PERM_W = 2
      PERM_X = 4
      PERM_RW = PERM_R | PERM_W
      PERM_RX = PERM_R | PERM_X
      PERM_RWX = PERM_R | PERM_W | PERM_X

      Region = Struct.new(:name, :base, :size, :permissions, keyword_init: true) do
        def includes?(addr)
          addr >= base && addr < base + size
        end
      end

      def initialize
        @pages           = {}
        @perms           = {}
        @regions         = []
        @write_callback  = nil
        @lenient         = false
      end

      attr_reader :regions
      attr_accessor :write_callback, :lenient

      def map(base, size, permissions: PERM_RW, name: nil, data: nil)
        raise Exe32Rb::MemoryError, "size must be positive" if size <= 0

        # Record the intent in @regions; actual page storage is allocated
        # lazily on first read/write. This keeps a 256 MiB scratch region
        # cheap when nothing's been written into it yet.
        @regions << Region.new(name: name, base: base, size: size, permissions: permissions)
        write(base, data) if data && !data.empty?
        nil
      end

      def mapped?(addr)
        @pages.key?(addr >> PAGE_BITS) || in_any_region?(addr)
      end

      def region_for(addr)
        @regions.find { |r| r.includes?(addr) }
      end

      def read(addr, size)
        return "".b if size == 0

        buf = String.new(capacity: size, encoding: Encoding::ASCII_8BIT)
        remaining = size
        cursor = addr
        while remaining > 0
          page = ensure_page(cursor, :read)
          if page.nil?
            # lenient mode: report zeros for unmapped reads
            chunk = [PAGE_SIZE - (cursor & PAGE_MASK), remaining].min
            buf << ("\x00".b * chunk)
          else
            offset_in_page = cursor & PAGE_MASK
            chunk = [PAGE_SIZE - offset_in_page, remaining].min
            buf << page.byteslice(offset_in_page, chunk)
          end
          cursor += chunk
          remaining -= chunk
        end
        buf
      end

      def write(addr, bytes)
        bytes = bytes.b
        return if bytes.empty?

        original_addr = addr
        original_size = bytes.bytesize
        cursor = addr
        offset_into_bytes = 0
        remaining = bytes.bytesize
        while remaining > 0
          page = ensure_page(cursor, :write)
          if page.nil?
            # lenient mode: drop writes to unmapped pages
            chunk = [PAGE_SIZE - (cursor & PAGE_MASK), remaining].min
          else
            offset_in_page = cursor & PAGE_MASK
            chunk = [PAGE_SIZE - offset_in_page, remaining].min
            page[offset_in_page, chunk] = bytes.byteslice(offset_into_bytes, chunk)
          end
          cursor += chunk
          offset_into_bytes += chunk
          remaining -= chunk
        end
        @write_callback&.call(original_addr, original_size)
        nil
      end

      private

      def ensure_page(addr, op)
        page_num = addr >> PAGE_BITS
        return @pages[page_num] if @pages.key?(page_num)
        unless in_any_region?(addr)
          return nil if @lenient

          raise Exe32Rb::MemoryError, format("%s of unmapped page at 0x%016X", op, addr)
        end

        @pages[page_num] = (+"\x00".b * PAGE_SIZE).force_encoding(Encoding::ASCII_8BIT)
      end

      def in_any_region?(addr)
        @regions.any? { |r| r.includes?(addr) }
      end

      public

      def read_u8(addr);  read(addr, 1).unpack1("C");  end
      def read_u16(addr); read(addr, 2).unpack1("v");  end
      def read_u32(addr); read(addr, 4).unpack1("V");  end
      def read_u64(addr); read(addr, 8).unpack1("Q<"); end

      def read_i8(addr);  v = read_u8(addr);  v < 0x80               ? v : v - 0x100;  end
      def read_i16(addr); v = read_u16(addr); v < 0x8000             ? v : v - 0x1_0000; end
      def read_i32(addr); v = read_u32(addr); v < 0x8000_0000        ? v : v - 0x1_0000_0000; end
      def read_i64(addr); v = read_u64(addr); v < 0x8000_0000_0000_0000 ? v : v - 0x1_0000_0000_0000_0000; end

      def write_u8(addr, v);  write(addr, [v & 0xFF].pack("C"));                  end
      def write_u16(addr, v); write(addr, [v & 0xFFFF].pack("v"));                end
      def write_u32(addr, v); write(addr, [v & 0xFFFF_FFFF].pack("V"));           end
      def write_u64(addr, v); write(addr, [v & 0xFFFF_FFFF_FFFF_FFFF].pack("Q<"));end

      def dump_regions
        @regions.map do |r|
          format("  %-12s  0x%016X .. 0x%016X  %s",
                 r.name || "?", r.base, r.base + r.size, perm_string(r.permissions))
        end.join("\n")
      end

      def perm_string(p)
        [(p & PERM_R) != 0 ? "r" : "-",
         (p & PERM_W) != 0 ? "w" : "-",
         (p & PERM_X) != 0 ? "x" : "-"].join
      end
    end
  end
end
