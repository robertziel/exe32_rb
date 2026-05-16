# frozen_string_literal: true

module Exe32Rb
  module Emulator
    # Top-level orchestrator: owns the loaded image, the virtual memory, the
    # CPU state, the decoder + executor, and the API dispatcher. Encapsulates
    # both the setup (mapping sections, stack, scratch, IAT patching) and the
    # fetch-decode-execute loop.
    class Machine
      STACK_SIZE         = 0x0010_0000   # 1 MiB
      SCRATCH_SIZE       = 0x1000_0000   # 256 MiB heap/scratch (room for installers
                                         # that VirtualAlloc large payload buffers)

      STACK_BASE_64      = 0x0000_7FFD_0000_0000
      SCRATCH_BASE_64    = 0x0000_7000_0000_0000
      TIB_BASE_64        = 0x0000_7FFE_FFFF_0000
      HALT_SENTINEL_64   = 0xDEAD_BEEF_DEAD_BEEF

      STACK_BASE_32      = 0x7000_0000
      SCRATCH_BASE_32    = 0x1000_0000  # well below stack/TIB so 16 MB fits
      TIB_BASE_32        = 0x7EFD_E000
      HALT_SENTINEL_32   = 0xDEAD_BEEF
      TIB_SIZE           = 0x1000
      HANDLE_BASE        = 0x4000_1000

      attr_reader :image, :memory, :cpu, :decoder, :executor, :dispatcher,
                  :exit_code, :steps_executed, :mode, :halt_sentinel
      attr_accessor :fs_root

      def initialize(image, trace: false)
        @image      = image
        @mode       = image.bitness || 64
        @memory     = Memory.new
        @cpu        = CPU.new(mode: @mode)
        @decoder    = Decoder.new(@memory, mode: @mode)
        @executor   = Executor.new(@cpu, @memory)
        @dispatcher = Api::Dispatcher.new(@memory, mode: @mode)
        @halted     = false
        @exit_code  = nil
        @trace      = trace
        @stack_base   = @mode == 64 ? STACK_BASE_64   : STACK_BASE_32
        @scratch_base = @mode == 64 ? SCRATCH_BASE_64 : SCRATCH_BASE_32
        @halt_sentinel = @mode == 64 ? HALT_SENTINEL_64 : HALT_SENTINEL_32
        @scratch_cursor = @scratch_base
        @steps_executed = 0
        @handles        = {}
        @next_handle    = HANDLE_BASE
      end

      attr_accessor :jit

      def configure
        ensure_supported_machine
        map_image
        map_stack
        map_scratch
        map_tib
        @dispatcher.install_builtins
        @dispatcher.bind_imports(@image)
        seed_initial_state
        compute_text_ranges
        @jit = nil
        self
      end

      # Enable the basic-block JIT. Off by default — turn on via
      # Machine#enable_jit or the --jit CLI flag. Off when tracing
      # (the per-instruction warn requires per-step dispatch).
      def enable_jit
        @jit = JIT.new(self) unless @trace
        self
      end

      # Compute the [start, end) virtual address ranges of executable
      # sections from the loaded image. Instructions decoded from addresses
      # inside these ranges go into the instruction cache (we assume
      # binaries don't self-modify their own .text — true for ~all
      # non-packed code). Writes outside these ranges (scratch, stack,
      # decoder-emitted thunks) bypass the cache.
      def compute_text_ranges
        @text_ranges = @image.sections.select(&:executable?).map do |s|
          base = @image.image_base + s.virtual_address
          size = [s.virtual_size, s.size_of_raw_data].max
          (base...(base + size))
        end
        # Fast path: most binaries have ONE .text section. Cache the lo/hi
        # for a tight integer compare in in_text?.
        if @text_ranges.size == 1
          @text_lo = @text_ranges[0].begin
          @text_hi = @text_ranges[0].end
        else
          @text_lo = @text_hi = nil
        end
        @instr_cache = {} # rip => Instruction
      end

      def in_text?(rip)
        if @text_lo
          rip >= @text_lo && rip < @text_hi
        else
          @text_ranges.any? { |r| r.cover?(rip) }
        end
      end

      def ensure_supported_machine
        case @image.machine
        when PE::Constants::MACHINE_AMD64
          raise Exe32Rb::ExecutionError, "image is AMD64 but mode is #{@mode}" unless @mode == 64
        when PE::Constants::MACHINE_I386
          raise Exe32Rb::ExecutionError, "image is I386 but mode is #{@mode}" unless @mode == 32
        else
          raise Exe32Rb::ExecutionError,
                "unsupported machine #{PE::Constants.machine_name(@image.machine)}"
        end
      end

      def halted?
        @halted
      end

      def step
        rip = @cpu.rip
        if rip == @halt_sentinel
          # If we returned here from an SEH handler that requested
          # ContinueSearch (eax == 1), walk to the next frame and try
          # again. The Ruby stack frame for the SEH dispatch is gone, so
          # we reconstruct it from @last_seh_state.
          if @last_seh_state && @cpu.registers.read32(Registers::RAX) == 1
            state = @last_seh_state
            @last_seh_state = nil
            next_frame = @memory.read_u32(state[:frame])
            if next_frame != 0xFFFF_FFFF && next_frame != 0
              # Re-raise with the same code, dispatching to next_frame
              @memory.write_u32(@cpu.fs_base, next_frame)
              return :seh if raise_guest_exception(state[:code], state[:params])
            end
          end
          @halted = true
          @exit_code ||= @cpu.registers.read32(Registers::RAX)
          return :halt
        end

        if @dispatcher.thunk?(rip)
          imp = @dispatcher.thunks[rip]
          trace_api(imp) if @trace
          @dispatcher.invoke(rip, self)
          return :api
        end

        # JIT (tier 3): compile a basic block (sequence of instructions
        # ending in a terminator) into a Ruby lambda that runs them all
        # in one dispatch. Returns instruction count for bulk counter
        # update. Falls back to single-step for thunks / non-.text addrs.
        if @jit && in_text?(rip)
          @steps_executed += @jit.run_block(rip)
          return :jit_block
        end

        # Instruction cache (JIT tier 1): re-decoding the same bytes
        # millions of times is the interpreter's biggest cost. Cache
        # Instruction objects keyed by rip for addresses in executable
        # sections (we assume those sections aren't self-modifying;
        # binaries that do rewrite their .text need a real invalidator).
        instr = @instr_cache[rip]
        if instr.nil?
          instr = @decoder.decode(rip)
          @instr_cache[rip] = instr if in_text?(rip)
        end
        trace_instr(instr) if @trace
        @cpu.rip = (rip + instr.length) & @cpu.address_mask
        @executor.execute(instr)
        @steps_executed += 1
        :step
      rescue Executor::HaltSignal => e
        @halted = true
        @exit_code = e.exit_code
        :halt
      rescue Exe32Rb::MemoryError => e
        # Try to dispatch through SEH first — that's what real Windows does
        # for access violations. If no handler is registered, fall through.
        if raise_guest_exception(0xC0000005, [parse_fault_address(e.message) || 0])
          :seh
        else
          raise
        end
      end

      # Synthesize a Win32 exception and dispatch through the SEH chain.
      # Returns true if a handler was found and rip was redirected, false
      # if the chain was empty / no handler available.
      def raise_guest_exception(code, params = [], flags: 0)
        return false unless @cpu.mode == 32

        frame = @memory.read_u32(@cpu.fs_base + 0)
        return false if frame == 0xFFFF_FFFF || frame == 0

        # Remember the dispatch parameters so the halt-sentinel handler can
        # walk to the next frame if this handler returns ContinueSearch.
        @last_seh_state = {code: code, params: params, frame: frame}

        rec_addr = scratch_alloc(80, zero: true)
        @memory.write_u32(rec_addr +  0, code)
        @memory.write_u32(rec_addr +  4, flags)
        @memory.write_u32(rec_addr +  8, 0)
        @memory.write_u32(rec_addr + 12, @cpu.rip)
        @memory.write_u32(rec_addr + 16, [params.size, 15].min)
        params.first(15).each_with_index do |v, i|
          @memory.write_u32(rec_addr + 20 + i * 4, v & 0xFFFF_FFFF)
        end

        ctx_addr = scratch_alloc(716, zero: true)
        @memory.write_u32(ctx_addr +   0, 0x10007)
        @memory.write_u32(ctx_addr + 156, @cpu.registers.read32(7))
        @memory.write_u32(ctx_addr + 160, @cpu.registers.read32(6))
        @memory.write_u32(ctx_addr + 164, @cpu.registers.read32(3))
        @memory.write_u32(ctx_addr + 168, @cpu.registers.read32(2))
        @memory.write_u32(ctx_addr + 172, @cpu.registers.read32(1))
        @memory.write_u32(ctx_addr + 176, @cpu.registers.read32(0))
        @memory.write_u32(ctx_addr + 180, @cpu.registers.read32(5))
        @memory.write_u32(ctx_addr + 184, @cpu.rip)
        @memory.write_u32(ctx_addr + 196, @cpu.rsp)

        handler = @memory.read_u32(frame + 4)
        return false if handler == 0 || handler == 0xFFFF_FFFF

        warn format("[SEH] dispatching code=0x%08X to handler=0x%08X frame=0x%08X",
                     code, handler, frame) if @trace
        @cpu.push32(@memory, 0)
        @cpu.push32(@memory, ctx_addr)
        @cpu.push32(@memory, frame)
        @cpu.push32(@memory, rec_addr)
        @cpu.push32(@memory, @halt_sentinel)
        @cpu.rip = handler
        true
      end

      def parse_fault_address(message)
        message.match(/0x([0-9A-Fa-f]+)/) { |m| m[1].to_i(16) }
      end

      def run(max_steps: 10_000_000)
        until @halted
          step
          if @steps_executed >= max_steps
            raise Exe32Rb::ExecutionError,
                  "machine ran for #{max_steps} steps without halting (rip=0x#{@cpu.rip.to_s(16)})"
          end
        end
        @exit_code
      rescue Exe32Rb::MemoryError => e
        $stderr.puts "\n--- fault ---"
        $stderr.puts e.message
        $stderr.puts "  rip = 0x#{@cpu.rip.to_s(16)}"
        $stderr.puts "  rsp = 0x#{@cpu.rsp.to_s(16)}"
        $stderr.puts "  steps = #{@steps_executed}"
        $stderr.puts @cpu.registers.to_s.lines.map { |l| "  #{l}" }.join
        raise
      end

      # Reserve a small scratch buffer and write a C-style string. Returns
      # the guest pointer.
      def scratch_strz(text)
        bytes = "#{text}\x00".b
        scratch_emit(bytes)
      end

      # UTF-16LE C-style string (LPCWSTR).
      def scratch_strz_w(text)
        bytes = +"".b
        text.each_codepoint do |cp|
          bytes << [cp & 0xFFFF].pack("v")
        end
        bytes << "\x00\x00".b
        scratch_emit(bytes)
      end

      # Bump-allocate `size` bytes of scratch; returns the guest pointer.
      def scratch_alloc(size, zero: false)
        return 0 if size <= 0

        size = (size + 0xF) & ~0xF # 16-byte align
        addr = @scratch_cursor
        @scratch_cursor += size
        # Pages are zero-initialized on first touch, and scratch is
        # bump-only (no reuse), so the bytes here are already zero.
        # The explicit memset was 80%+ of allocation cost in hot paths.
        addr
      end

      def scratch_emit(bytes)
        addr = @scratch_cursor
        @memory.write(addr, bytes)
        @scratch_cursor += bytes.bytesize
        addr
      end

      # ----------------------------------------------------------------
      # Host-backed handles
      # ----------------------------------------------------------------

      # Hand the guest a synthetic 32-bit handle that maps back to a host
      # IO object (a File, $stdin/$stdout, or anything that responds to the
      # usual IO API).
      def register_handle(io)
        handle = @next_handle
        @next_handle += 1
        @handles[handle] = io
        handle
      end

      def lookup_handle(handle)
        @handles[handle]
      end

      def close_handle(handle)
        io = @handles.delete(handle)
        return false unless io

        begin
          io.close unless io.closed?
        rescue IOError, Errno::EBADF
          # already closed; nothing to do
        end
        true
      end

      # ----------------------------------------------------------------
      # Guest-string readers
      # ----------------------------------------------------------------

      # Read a UTF-16LE C string from guest memory and return a UTF-8 String.
      def read_wstring(addr)
        return "" if addr.nil? || addr == 0

        bytes = +"".b
        pos = addr
        loop do
          pair = @memory.read(pos, 2)
          break if pair == "\x00\x00".b

          bytes << pair
          pos += 2
        end
        bytes.force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8)
      end

      # Read an ASCII C string from guest memory.
      def read_cstring(addr)
        return "" if addr.nil? || addr == 0

        bytes = +"".b
        pos = addr
        loop do
          b = @memory.read_u8(pos)
          break if b == 0

          bytes << b.chr.b
          pos += 1
        end
        bytes
      end

      private

      def map_image
        # Headers region (everything up to first section's RVA). We round up
        # to a page so subsequent section maps don't collide.
        header_size = align_to_page(@image.size_of_headers)
        @memory.map(@image.image_base, header_size,
                    permissions: Memory::PERM_R, name: "headers")

        # We need the original file bytes for the headers in case code reads
        # them at runtime (rare, but harmless).
        header_bytes = File.binread(@image.path, @image.size_of_headers)
        @memory.write(@image.image_base, header_bytes)

        @image.sections.each do |section|
          perm = 0
          perm |= Memory::PERM_R if section.readable?
          perm |= Memory::PERM_W if section.writable?
          perm |= Memory::PERM_X if section.executable?
          perm = Memory::PERM_R if perm == 0

          vsize = [section.virtual_size, section.size_of_raw_data].max
          next if vsize == 0

          base = @image.image_base + section.virtual_address
          @memory.map(base, align_to_page(vsize), permissions: perm, name: section.name)
          @memory.write(base, section.raw_data) unless section.raw_data.empty?
        end
      end

      def map_stack
        @memory.map(@stack_base, STACK_SIZE,
                    permissions: Memory::PERM_RW, name: "stack")
        # Leave a little headroom and align to 16 (ABI alignment for calls).
        @cpu.rsp = (@stack_base + STACK_SIZE - 0x100) & ~0xF
      end

      def map_scratch
        @memory.map(@scratch_base, SCRATCH_SIZE,
                    permissions: Memory::PERM_RW, name: "scratch")
      end

      # Minimal Thread Information Block — enough for compiler-emitted FS:[...]
      # accesses (SEH chain at offset 0, self pointer, stack limits) to read
      # plausible values instead of crashing on address 0.
      def map_tib
        tib_base = @mode == 32 ? TIB_BASE_32 : TIB_BASE_64
        @memory.map(tib_base, TIB_SIZE, permissions: Memory::PERM_RW, name: "tib")

        # TIB page layout (offsets within the 4 KiB region):
        #   0x000..0x100   real TIB fields (SEH, stack, self, ids, TLS, PEB ptr)
        #   0x100..0x500   TlsSlots — pointer array of TLS data per slot
        #   0x500..0x800   TLS data — shared zero region every slot points to
        #   0x800..0x1000  PEB (zero-filled stub)
        tls_array_offset = 0x100
        tls_data_offset  = 0x500
        tls_data_addr    = tib_base + tls_data_offset

        if @mode == 32
          @cpu.fs_base = tib_base
          @memory.write_u32(tib_base + 0x00, 0xFFFF_FFFF)             # ExceptionList: no handler
          @memory.write_u32(tib_base + 0x04, @stack_base + STACK_SIZE) # StackBase
          @memory.write_u32(tib_base + 0x08, @stack_base)              # StackLimit
          @memory.write_u32(tib_base + 0x18, tib_base)                 # Self
          @memory.write_u32(tib_base + 0x20, 1)                        # ProcessId
          @memory.write_u32(tib_base + 0x24, 1)                        # ThreadId
          @memory.write_u32(tib_base + 0x2C, tib_base + tls_array_offset) # TlsSlots
          @memory.write_u32(tib_base + 0x30, tib_base + 0x800)         # PEB

          # Point every TLS slot at the shared zero region. Static-TLS readers
          # do `mov edx, fs:[0x2C]; mov eax, [edx + N*4]; mov ..., [eax]` —
          # this makes the final deref land on mapped (zero) memory.
          256.times do |i|
            @memory.write_u32(tib_base + tls_array_offset + i * 4, tls_data_addr)
          end
        else
          @cpu.gs_base = tib_base
          @memory.write_u64(tib_base + 0x00, 0xFFFF_FFFF_FFFF_FFFF)
          @memory.write_u64(tib_base + 0x08, @stack_base + STACK_SIZE)
          @memory.write_u64(tib_base + 0x10, @stack_base)
          @memory.write_u64(tib_base + 0x30, tib_base)
          @memory.write_u64(tib_base + 0x58, tib_base + tls_array_offset) # TlsSlots
          @memory.write_u64(tib_base + 0x60, tib_base + 0x800)
          64.times do |i|
            @memory.write_u64(tib_base + tls_array_offset + i * 8, tls_data_addr)
          end
        end
      end

      def seed_initial_state
        @cpu.rip = @image.entry_point
        # Push a sentinel return address. If entry's RET ever fires, RIP
        # becomes this and the step loop halts gracefully.
        @cpu.push_native(@memory, @halt_sentinel)
      end

      def align_to_page(size)
        (size + Memory::PAGE_MASK) & ~Memory::PAGE_MASK
      end

      def trace_instr(instr)
        warn instr.to_s
      end

      def trace_api(imp)
        warn format("              => %s", imp.display_name)
      end
    end
  end
end
