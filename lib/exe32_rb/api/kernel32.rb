# frozen_string_literal: true

require "tmpdir"
require "fileutils"

module Exe32Rb
  module Api
    # Minimal kernel32.dll surface — enough to take a CRT-less hello-world
    # off the ground. Handlers take (machine, args) where args is an array
    # of integers already read from registers/stack per the calling
    # convention. The integer returned becomes the API's return value.
    module Kernel32
      STD_INPUT_HANDLE  = 0xFFFF_FFF6 # -10 as u32
      STD_OUTPUT_HANDLE = 0xFFFF_FFF5 # -11 as u32
      STD_ERROR_HANDLE  = 0xFFFF_FFF4 # -12 as u32

      # Opaque handle values. The guest only compares them; we just need
      # them to be distinguishable.
      HANDLE_STDIN  = 0x4000_0010
      HANDLE_STDOUT = 0x4000_0011
      HANDLE_STDERR = 0x4000_0012

      def self.install(dispatcher)
        dispatcher.install_handler("kernel32.dll", "GetStdHandle", args: 1) do |_machine, args|
          case args[0] & 0xFFFF_FFFF
          when STD_INPUT_HANDLE  then HANDLE_STDIN
          when STD_OUTPUT_HANDLE then HANDLE_STDOUT
          when STD_ERROR_HANDLE  then HANDLE_STDERR
          else 0xFFFF_FFFF_FFFF_FFFF # INVALID_HANDLE_VALUE
          end
        end

        dispatcher.install_handler("kernel32.dll", "WriteFile", args: 5) do |machine, args|
          handle    = args[0]
          buf_addr  = args[1]
          nbytes    = args[2] & 0xFFFF_FFFF
          written_p = args[3]
          _overlap  = args[4]

          io = case handle
               when HANDLE_STDOUT then $stdout
               when HANDLE_STDERR then $stderr
               else machine.lookup_handle(handle)
               end
          next 0 unless io

          data = machine.memory.read(buf_addr, nbytes)
          io.write(data)
          io.flush

          machine.memory.write_u32(written_p, nbytes) if written_p != 0
          1
        end

        # ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
        dispatcher.install_handler("kernel32.dll", "ReadFile", args: 5) do |machine, args|
          handle = args[0]
          buf    = args[1]
          nbytes = args[2] & 0xFFFF_FFFF
          read_p = args[3]

          io = handle == HANDLE_STDIN ? $stdin : machine.lookup_handle(handle)
          next 0 unless io

          data = io.read(nbytes) || +"".b
          machine.memory.write(buf, data) unless data.empty?
          machine.memory.write_u32(read_p, data.bytesize) if read_p != 0
          1
        end

        # CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        #             lpSecurityAttributes, dwCreationDisposition,
        #             dwFlagsAndAttributes, hTemplateFile)
        dispatcher.install_handler("kernel32.dll", "CreateFileW", args: 7) do |machine, args|
          path   = machine.read_wstring(args[0])
          access = args[1] & 0xFFFF_FFFF
          disp   = args[4] & 0xFFFF_FFFF
          if path.empty? && access == 0x8000_0000 && disp == 3
            # GENERIC_READ + OPEN_EXISTING on an empty path. The binary
            # almost certainly meant to open its own image (e.g. for
            # self-extraction) but a string copy lost the bytes. Fall
            # back to the image path so the unpacker can proceed.
            path = File.absolute_path(machine.image.path)
            warn "[CreateFileW] empty path; falling back to image (#{path})"
          else
            translated = Api::WinFS.translate(machine.fs_root, path)
            if translated != path
              warn format("[CreateFileW] %s -> %s", path, translated)
              FileUtils.mkdir_p(File.dirname(translated)) rescue nil
              path = translated
            end
          end
          r = (access & 0x8000_0000) != 0
          w = (access & 0x4000_0000) != 0

          mode = case disp
                 when 1, 2 # CREATE_NEW or CREATE_ALWAYS (we won't fail-if-exists)
                   r && w ? "wb+" : (w ? "wb" : "rb")
                 when 3    # OPEN_EXISTING
                   r && w ? "rb+" : (w ? "wb" : "rb")
                 when 4    # OPEN_ALWAYS
                   if File.exist?(path)
                     r && w ? "rb+" : (w ? "ab" : "rb")
                   else
                     r && w ? "wb+" : "wb"
                   end
                 when 5    # TRUNCATE_EXISTING
                   "wb"
                 else
                   "rb"
                 end

          begin
            io = File.open(path, mode)
            machine.register_handle(io)
          rescue Errno::ENOENT, Errno::EEXIST, Errno::EACCES, Errno::EISDIR, IOError
            0xFFFF_FFFF # INVALID_HANDLE_VALUE
          end
        end

        dispatcher.install_handler("kernel32.dll", "CloseHandle", args: 1) do |machine, args|
          machine.close_handle(args[0]) ? 1 : 0
        end

        dispatcher.install_handler("kernel32.dll", "SetFilePointer", args: 4) do |machine, args|
          io = machine.lookup_handle(args[0])
          next 0xFFFF_FFFF unless io

          offset = args[1] & 0xFFFF_FFFF
          offset -= 0x1_0000_0000 if offset >= 0x8000_0000
          whence = {0 => IO::SEEK_SET, 1 => IO::SEEK_CUR, 2 => IO::SEEK_END}[args[3] & 0xFFFF_FFFF] || IO::SEEK_SET
          begin
            io.seek(offset, whence)
            io.pos & 0xFFFF_FFFF
          rescue IOError, Errno::EINVAL
            0xFFFF_FFFF
          end
        end

        dispatcher.install_handler("kernel32.dll", "GetFileSize", args: 2) do |machine, args|
          io = machine.lookup_handle(args[0])
          next 0xFFFF_FFFF unless io

          begin
            io.size & 0xFFFF_FFFF
          rescue IOError
            0xFFFF_FFFF
          end
        end

        # FindResource* walks the parsed .rsrc tree. We return the
        # IMAGE_RESOURCE_DATA_ENTRY virtual address as the HRSRC handle —
        # LoadResource reads OffsetToData out of it via guest memory just
        # like real Windows would, so the handle round-trips through any
        # caller that inspects it.
        resolve_name = ->(machine, ptr) {
          # MAKEINTRESOURCE places the integer in the low 16 bits with high
          # word zero. Anything else is a wide string pointer.
          if (ptr & 0xFFFF_0000) == 0 && ptr != 0
            ptr & 0xFFFF
          elsif ptr == 0
            nil
          else
            machine.read_wstring(ptr)
          end
        }

        find_resource = ->(machine, args, type_first: false) {
          if type_first
            type = resolve_name.call(machine, args[1])
            name = resolve_name.call(machine, args[2])
          else
            name = resolve_name.call(machine, args[1])
            type = resolve_name.call(machine, args[2])
          end
          entry = machine.image.find_resource(type, name)
          entry ? machine.image.image_base + entry[:entry_rva] : 0
        }

        dispatcher.install_handler("kernel32.dll", "FindResourceA", args: 3) do |machine, args|
          find_resource.call(machine, args)
        end
        dispatcher.install_handler("kernel32.dll", "FindResourceW", args: 3) do |machine, args|
          find_resource.call(machine, args)
        end
        dispatcher.install_handler("kernel32.dll", "FindResourceExW", args: 4) do |machine, args|
          # Args: hModule, lpType, lpName, wLanguage  (type before name here)
          find_resource.call(machine, args, type_first: true)
        end

        dispatcher.install_handler("kernel32.dll", "SizeofResource", args: 2) do |machine, args|
          entry_va = args[1] & 0xFFFF_FFFF
          next 0 if entry_va == 0

          machine.memory.read_u32(entry_va + 4) # Size field of IMAGE_RESOURCE_DATA_ENTRY
        end

        dispatcher.install_handler("kernel32.dll", "LoadResource", args: 2) do |machine, args|
          entry_va = args[1] & 0xFFFF_FFFF
          next 0 if entry_va == 0

          data_rva = machine.memory.read_u32(entry_va) # OffsetToData (RVA in image)
          machine.image.image_base + data_rva
        end
        dispatcher.install_handler("kernel32.dll", "LockResource", args: 1) { |_, args| args[0] }

        dispatcher.install_handler("kernel32.dll", "DeleteFileW", args: 1) do |machine, args|
          File.delete(Api::WinFS.translate(machine.fs_root, machine.read_wstring(args[0])))
          1
        rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR
          0
        end

        dispatcher.install_handler("kernel32.dll", "GetFileAttributesW", args: 1) do |machine, args|
          guest = machine.read_wstring(args[0])
          host  = Api::WinFS.translate(machine.fs_root, guest)
          if !File.exist?(host) then 0xFFFF_FFFF
          elsif File.directory?(host) then 0x10
          else 0x80
          end
        end

        dispatcher.install_handler("kernel32.dll", "CreateDirectoryW", args: 2) do |machine, args|
          guest_path = machine.read_wstring(args[0])
          if guest_path.empty?
            dispatcher.set_last_error(123) # ERROR_INVALID_NAME
            warn "[CreateDirectoryW] (empty path) -> failure"
            next 0
          end
          host_path = Api::WinFS.translate(machine.fs_root, guest_path)
          warn format("[CreateDirectoryW] %s -> %s", guest_path.inspect, host_path)
          FileUtils.mkdir_p(File.dirname(host_path))
          begin
            Dir.mkdir(host_path)
          rescue Errno::EEXIST
            dispatcher.set_last_error(183) # ERROR_ALREADY_EXISTS
            next 0
          rescue Errno::ENOENT, Errno::EACCES => e
            dispatcher.set_last_error(e.is_a?(Errno::ENOENT) ? 3 : 5)
            next 0
          end
          dispatcher.set_last_error(0)
          1
        end

        dispatcher.install_handler("kernel32.dll", "FindFirstFileW", args: 2) do |machine, args|
          guest_path = machine.read_wstring(args[0])
          warn format("[FindFirstFileW] %s", guest_path.inspect)
          0xFFFF_FFFF # INVALID_HANDLE_VALUE — we don't model directory enum
        end

        dispatcher.install_handler("kernel32.dll", "ExitProcess", args: 1) do |_machine, args|
          raise Emulator::Executor::HaltSignal.new(args[0] & 0xFFFF_FFFF)
        end

        # RaiseException is non-returning in real Windows: it walks the SEH
        # chain. We don't model SEH, so returning to the guest lands the
        # CPU in undefined territory. Halt cleanly instead and surface the
        # exception code so the trigger is visible.
        # Minimal registry stubs: pretend the key opens and every value reads
        # back as empty. The installer is checking system state (Windows
        # version, presence of components) and a blanket "yes that exists,
        # but is empty" is usually friendlier than ERROR_FILE_NOT_FOUND.
        dispatcher.install_handler("advapi32.dll", "RegOpenKeyExW", args: 5) do |machine, args|
          phk = args[4] & 0xFFFF_FFFF
          machine.memory.write_u32(phk, 0x8000_0001) if phk != 0
          0 # ERROR_SUCCESS
        end
        dispatcher.install_handler("advapi32.dll", "RegOpenKeyExA", args: 5) do |machine, args|
          phk = args[4] & 0xFFFF_FFFF
          machine.memory.write_u32(phk, 0x8000_0001) if phk != 0
          0
        end
        dispatcher.install_handler("advapi32.dll", "RegQueryValueExW", args: 6) do |machine, args|
          lp_type     = args[2] & 0xFFFF_FFFF
          lp_data     = args[3] & 0xFFFF_FFFF
          lpcb_data   = args[4] & 0xFFFF_FFFF
          # Pretend every value is a DWORD = 0x0409 (en-US LCID). That's
          # what Delphi RTL is usually fishing for; returning 0 was making
          # it interpret "no locale" and raise.
          machine.memory.write_u32(lp_type, 4) if lp_type != 0
          if lp_data != 0 && lpcb_data != 0
            avail = machine.memory.read_u32(lpcb_data)
            if avail >= 4
              machine.memory.write_u32(lp_data, 0x0409)
              machine.memory.write_u32(lpcb_data, 4)
            end
          end
          0
        end
        dispatcher.install_handler("advapi32.dll", "RegQueryValueExA", args: 6) do |machine, args|
          lp_type   = args[2] & 0xFFFF_FFFF
          lp_data   = args[3] & 0xFFFF_FFFF
          lpcb_data = args[4] & 0xFFFF_FFFF
          machine.memory.write_u32(lp_type, 4) if lp_type != 0
          if lp_data != 0 && lpcb_data != 0
            avail = machine.memory.read_u32(lpcb_data)
            if avail >= 4
              machine.memory.write_u32(lp_data, 0)
              machine.memory.write_u32(lpcb_data, 4)
            end
          end
          0
        end

        # RaiseException dispatches through the FS:[0] SEH chain. We
        # synthesize an EXCEPTION_RECORD and a near-minimal CONTEXT on
        # scratch, then jump to the first handler. The handler returns via
        # an established convention (often through RtlUnwind), so we let
        # the guest's own RTL drive the catch/finally logic.
        dispatcher.install_handler("kernel32.dll", "RaiseException", args: 4) do |machine, args|
          code  = args[0] & 0xFFFF_FFFF
          flags = args[1] & 0xFFFF_FFFF
          nargs = args[2] & 0xFFFF_FFFF
          argp  = args[3] & 0xFFFF_FFFF

          # Delphi-RTL exceptions (EXCEPTION_DELPHI* codes) pass a Delphi
          # Exception object pointer in args. obj+0 = VMT, obj+4 = FMessage
          # (a UnicodeString — pointer with length at [ptr-4]). VMT-56 is
          # a pointer to ClassName (Pascal ShortString: length byte + chars).
          if code == 0x0EEDFADE && nargs >= 1 && argp != 0
            obj = machine.memory.read_u32(argp) rescue 0
            if obj != 0
              vmt = machine.memory.read_u32(obj) rescue 0
              cls_name = ""
              if vmt != 0
                name_ptr = machine.memory.read_u32((vmt - 56) & 0xFFFF_FFFF) rescue 0
                if name_ptr != 0
                  len = machine.memory.read_u8(name_ptr) rescue 0
                  if len > 0 && len < 100
                    cls_name = (1..len).map { |i| machine.memory.read_u8(name_ptr + i) }.pack('C*') rescue ""
                  end
                end
              end
              msg_text = ""
              msg_ptr = machine.memory.read_u32(obj + 4) rescue 0
              if msg_ptr != 0
                begin
                  len = machine.memory.read_u32((msg_ptr - 4) & 0xFFFF_FFFF)
                  if len > 0 && len < 1000
                    bytes = (0...len*2).map { |i| machine.memory.read_u8(msg_ptr + i) }.pack('C*')
                    msg_text = bytes.force_encoding('UTF-16LE')
                                    .encode('UTF-8', invalid: :replace, undef: :replace)
                  end
                rescue
                end
              end
              warn format("[Delphi Exception] class=%s message=%s",
                          cls_name.empty? ? "?" : cls_name,
                          msg_text.empty? ? "(none)" : msg_text.inspect)
            end
          end

          # Read the head of the SEH chain from the TIB (FS:[0]).
          frame = machine.memory.read_u32(machine.cpu.fs_base + 0)
          if frame == 0xFFFF_FFFF || frame == 0
            warn format("[RaiseException] code=0x%08X — empty SEH chain, halting", code)
            raise Emulator::Executor::HaltSignal.new(code)
          end

          # Build EXCEPTION_RECORD in scratch: { code, flags, next, address,
          # numparams, params[15] }. 80 bytes.
          rec_addr = machine.scratch_alloc(80, zero: true)
          machine.memory.write_u32(rec_addr +  0, code)
          machine.memory.write_u32(rec_addr +  4, flags)
          machine.memory.write_u32(rec_addr +  8, 0)              # ExceptionRecord*
          machine.memory.write_u32(rec_addr + 12, machine.cpu.rip) # ExceptionAddress
          machine.memory.write_u32(rec_addr + 16, [nargs, 15].min) # NumberParameters
          if argp != 0 && nargs > 0
            [nargs, 15].min.times do |i|
              machine.memory.write_u32(rec_addr + 20 + i * 4,
                                       machine.memory.read_u32(argp + i * 4))
            end
          end

          # Build a minimal CONTEXT block (716 bytes). We zero it; the guest
          # mostly cares about ContextFlags + EIP/ESP/EBP.
          ctx_addr = machine.scratch_alloc(716, zero: true)
          machine.memory.write_u32(ctx_addr +   0, 0x10007) # CONTEXT_FULL
          machine.memory.write_u32(ctx_addr + 156, machine.cpu.registers.read32(7)) # Edi
          machine.memory.write_u32(ctx_addr + 160, machine.cpu.registers.read32(6)) # Esi
          machine.memory.write_u32(ctx_addr + 164, machine.cpu.registers.read32(3)) # Ebx
          machine.memory.write_u32(ctx_addr + 168, machine.cpu.registers.read32(2)) # Edx
          machine.memory.write_u32(ctx_addr + 172, machine.cpu.registers.read32(1)) # Ecx
          machine.memory.write_u32(ctx_addr + 176, machine.cpu.registers.read32(0)) # Eax
          machine.memory.write_u32(ctx_addr + 180, machine.cpu.registers.read32(5)) # Ebp
          machine.memory.write_u32(ctx_addr + 184, machine.cpu.rip)                  # Eip
          machine.memory.write_u32(ctx_addr + 196, machine.cpu.rsp)                  # Esp

          # Read the EXCEPTION_REGISTRATION_RECORD at `frame`:
          # struct { prev: u32, handler: u32 }
          handler = machine.memory.read_u32(frame + 4)
          warn format("[RaiseException] code=0x%08X -> handler=0x%08X frame=0x%08X",
                       code, handler, frame)

          # RaiseException is __stdcall (callee-pops), so first reclaim its
          # own return address + 4 args from the guest stack — they would
          # normally have been popped by Convention.cleanup. We then push a
          # fresh frame for the handler:
          #   esp -> halt_sentinel (handler return)
          #          ExceptionRecord*
          #          EstablisherFrame
          #          ContextRecord*
          #          DispatcherContext (unused)
          machine.cpu.rsp = (machine.cpu.rsp + 4 * (1 + 4)) & machine.cpu.address_mask
          machine.cpu.push32(machine.memory, 0)
          machine.cpu.push32(machine.memory, ctx_addr)
          machine.cpu.push32(machine.memory, frame)
          machine.cpu.push32(machine.memory, rec_addr)
          machine.cpu.push32(machine.memory, machine.halt_sentinel)
          machine.cpu.rip = handler

          Api::Dispatcher::SKIP_CLEANUP
        end

        # RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue)
        # Walk the SEH chain from current FS:[0] down to TargetFrame, popping
        # each frame off the chain. If TargetFrame is 0/NULL, walk the whole
        # chain (exit-process unwind). We don't call termination handlers
        # ourselves; we just adjust FS:[0] and let the guest resume.
        dispatcher.install_handler("kernel32.dll", "RtlUnwind", args: 4) do |machine, args|
          target_frame = args[0] & 0xFFFF_FFFF
          target_ip    = args[1] & 0xFFFF_FFFF
          warn format("[RtlUnwind] target_frame=0x%08X target_ip=0x%08X",
                       target_frame, target_ip)

          frame = machine.memory.read_u32(machine.cpu.fs_base + 0)
          steps = 0
          while frame != 0xFFFF_FFFF && frame != target_frame && steps < 64
            frame = machine.memory.read_u32(frame + 0) # follow .prev
            steps += 1
          end
          machine.memory.write_u32(machine.cpu.fs_base + 0, frame)
          0
        end

        # Track LastError properly so Win32 error-check patterns work.
        # Many Delphi code paths do: call API; if returns 0, GetLastError;
        # if error == X then ...; without real LastError they loop or assume
        # success-with-failure-marker.
        last_error = 0
        machine.define_singleton_method(:set_last_error) { |code| last_error = code & 0xFFFF_FFFF } if false
        dispatcher.install_handler("kernel32.dll", "GetLastError", args: 0) do |_machine, _args|
          last_error
        end
        dispatcher.install_handler("kernel32.dll", "SetLastError", args: 1) do |_machine, args|
          last_error = args[0] & 0xFFFF_FFFF
          0
        end
        # Expose last_error to other handlers via a method on the dispatcher.
        dispatcher.define_singleton_method(:set_last_error) do |code|
          last_error = code & 0xFFFF_FFFF
        end

        dispatcher.install_handler("kernel32.dll", "GetCommandLineA", args: 0) do |machine, _args|
          machine.scratch_strz("")
        end

        dispatcher.install_handler("kernel32.dll", "GetModuleHandleA", args: 1) do |machine, args|
          # NULL means "the current module". For named modules we don't track
          # them; pretend they're all the EXE's base. Callers usually check
          # against zero before doing anything dangerous.
          args[0] == 0 ? machine.image.image_base : machine.image.image_base
        end

        dispatcher.install_handler("kernel32.dll", "GetModuleHandleW", args: 1) do |machine, _args|
          machine.image.image_base
        end

        dispatcher.install_handler("kernel32.dll", "GetModuleFileNameA", args: 3) do |machine, args|
          buf, n = args[1], args[2] & 0xFFFF_FFFF
          path = File.absolute_path(machine.image.path).b
          path = path.byteslice(0, n - 1) if n > 0 && path.bytesize >= n
          machine.memory.write(buf, path + "\x00".b) if buf != 0 && n > 0
          path.bytesize
        end

        dispatcher.install_handler("kernel32.dll", "GetModuleFileNameW", args: 3) do |machine, args|
          buf, n = args[1], args[2] & 0xFFFF_FFFF
          path = File.absolute_path(machine.image.path)
          encoded = +"".b
          path.each_codepoint { |c| encoded << [c & 0xFFFF].pack("v") }
          total_chars = encoded.bytesize / 2
          if buf != 0 && n > 0
            copy = [total_chars, n - 1].min
            machine.memory.write(buf, encoded.byteslice(0, copy * 2))
            machine.memory.write_u16(buf + copy * 2, 0) # null terminator
            copy
          else
            total_chars
          end
        end

        # Tick counter that actually advances — InnoSetup uses GetTickCount as
        # entropy for temp directory names ("is-NNN.tmp"). Returning a fixed
        # value gives the same path every time and breaks file-existence checks.
        tick = 0x1000
        dispatcher.install_handler("kernel32.dll", "GetTickCount", args: 0) do |_, _|
          tick += 1
          tick
        end

        dispatcher.install_handler("kernel32.dll", "GetVersion",         args: 0) { |_, _| 0x0023_0A00 } # Win10 6.0 build 10 form
        dispatcher.install_handler("kernel32.dll", "GetVersionExA",      args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetVersionExW",      args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetCurrentProcess",  args: 0) { |_, _| 0xFFFF_FFFF }
        dispatcher.install_handler("kernel32.dll", "GetCurrentProcessId", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetCurrentThreadId", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "IsProcessorFeaturePresent", args: 1) { |_, _| 0 }
        # Counters that actually advance. InnoSetup and other installers use
        # these as entropy for unique temp file names; returning a fixed
        # value produces identical names every call, defeating uniqueness
        # tests and breaking path-build logic.
        perf_counter = 0
        dispatcher.install_handler("kernel32.dll", "QueryPerformanceCounter", args: 1) do |machine, args|
          perf_counter += 1
          machine.memory.write_u64(args[0], perf_counter) if args[0] != 0
          1
        end
        dispatcher.install_handler("kernel32.dll", "QueryPerformanceFrequency", args: 1) do |machine, args|
          machine.memory.write_u64(args[0], 1_000_000) if args[0] != 0
          1
        end
        # Return a non-zero Windows FILETIME so date-formatting code doesn't
        # produce weird zero results.
        dispatcher.install_handler("kernel32.dll", "GetSystemTimeAsFileTime", args: 1) do |machine, args|
          # FILETIME for 2024-01-01 (in 100-ns intervals since 1601).
          ft = 0x01DA_3FE0_DDA0_F000
          machine.memory.write_u64(args[0], ft) if args[0] != 0
          0
        end

        # Heap with FastMM-shaped headers. Delphi RTL bypasses the system
        # heap when it owns memory, but for the few code paths that do read
        # back kernel32 heap blocks, [ptr-4] must contain a "block size word"
        # whose high bits encode size and low 4 bits encode flags. Without
        # this, Delphi's validator pulls a bogus size and computes a
        # nonsense trailing-tag address.
        #
        # Layout for each allocation:
        #   [ptr-8]  reserved / next-pointer slot (zero)
        #   [ptr-4]  rounded_size | flags   ; low 4 bits = 0 => "regular block"
        #   [ptr..]  user bytes (rounded up to 16)
        #   [ptr+size-4] trailing tag (zero)
        heap_alloc = ->(machine, args) {
          size = args[2] & 0xFFFF_FFFF
          next 0 if size == 0

          rounded = (size + 0xF) & ~0xF
          # 16 bytes of header before, 8 bytes of trailer after
          base = machine.scratch_alloc(rounded + 24, zero: true)
          next 0 if base == 0

          ret = base + 16
          machine.memory.write_u32(ret - 4, rounded) # size word, flag bits = 0
          ret
        }
        dispatcher.install_handler("kernel32.dll", "HeapCreate", args: 3) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapDestroy", args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetProcessHeap", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapAlloc",  args: 3, &heap_alloc)
        dispatcher.install_handler("kernel32.dll", "LocalAlloc", args: 2) do |machine, args|
          heap_alloc.call(machine, [0, args[0], args[1]])
        end
        dispatcher.install_handler("kernel32.dll", "GlobalAlloc", args: 2) do |machine, args|
          heap_alloc.call(machine, [0, args[0], args[1]])
        end
        dispatcher.install_handler("kernel32.dll", "LocalFree",  args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "GlobalFree", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "HeapFree", args: 3) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapSize", args: 3) do |machine, args|
          ptr = args[2] & 0xFFFF_FFFF
          ptr == 0 ? 0 : machine.memory.read_u32(ptr - 4) & 0xFFFF_FFF0
        end
        dispatcher.install_handler("kernel32.dll", "HeapReAlloc", args: 4) do |machine, args|
          heap_alloc.call(machine, [0, args[1], args[3]])
        end

        # Critical sections — no-ops for a single-threaded emulator.
        %w[InitializeCriticalSection DeleteCriticalSection
           EnterCriticalSection LeaveCriticalSection
           InitializeCriticalSectionAndSpinCount].each do |fn|
          n_args = fn == "InitializeCriticalSectionAndSpinCount" ? 2 : 1
          dispatcher.install_handler("kernel32.dll", fn, args: n_args) { |_, _| 1 }
        end

        # TLS — return distinct slot indices and store per-thread (single
        # thread, so a flat hash works).
        tls_next = 0
        tls_slots = {}
        dispatcher.install_handler("kernel32.dll", "TlsAlloc", args: 0) do
          tls_next += 1
        end
        dispatcher.install_handler("kernel32.dll", "TlsSetValue", args: 2) do |_, args|
          tls_slots[args[0]] = args[1]
          1
        end
        dispatcher.install_handler("kernel32.dll", "TlsGetValue", args: 1) do |_, args|
          tls_slots[args[0]] || 0
        end
        dispatcher.install_handler("kernel32.dll", "TlsFree", args: 1) { |_, _| 1 }

        # Module loading — pretend success but return a sentinel handle that
        # callers can do nothing useful with. GetProcAddress returning 0 makes
        # well-behaved code fall back; misbehaving code crashes.
        dispatcher.install_handler("kernel32.dll", "LoadLibraryA",  args: 1) { |_, _| 0x4000_0100 }
        dispatcher.install_handler("kernel32.dll", "LoadLibraryW",  args: 1) { |_, _| 0x4000_0100 }
        dispatcher.install_handler("kernel32.dll", "LoadLibraryExA", args: 3) { |_, _| 0x4000_0100 }
        dispatcher.install_handler("kernel32.dll", "LoadLibraryExW", args: 3) { |_, _| 0x4000_0100 }
        dispatcher.install_handler("kernel32.dll", "FreeLibrary",    args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetProcAddress", args: 2) { |_, _| 0 }

        # Virtual memory — back with the scratch allocator.
        dispatcher.install_handler("kernel32.dll", "VirtualAlloc", args: 4) do |machine, args|
          machine.scratch_alloc(args[1] & 0xFFFF_FFFF, zero: true)
        end
        dispatcher.install_handler("kernel32.dll", "VirtualFree", args: 3) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "VirtualProtect", args: 4) do |machine, args|
          # Write old protection = whatever was requested.
          machine.memory.write_u32(args[3], args[2] & 0xFFFF_FFFF) if args[3] != 0
          1
        end

        # Misc.
        dispatcher.install_handler("kernel32.dll", "GetCommandLineW", args: 0) do |machine, _|
          machine.scratch_strz_w("\"#{machine.image.path}\"")
        end

        # Environment variables — return sensible host paths for TEMP-ish ones.
        # An installer that gets TEMP="" can't build paths like "TEMP\is-NN.tmp"
        # and falls into bad code paths.
        # Synthetic Windows-style paths. The guest will mix these into its
        # own concatenations and we want the result to look like a Windows
        # path. We translate back to host paths at file-I/O time elsewhere.
        env_overrides = {
          "TEMP"         => "C:\\Temp",
          "TMP"          => "C:\\Temp",
          "USERPROFILE"  => "C:\\Users\\exe32_rb",
          "APPDATA"      => "C:\\Users\\exe32_rb\\AppData\\Roaming",
          "LOCALAPPDATA" => "C:\\Users\\exe32_rb\\AppData\\Local",
          "PROGRAMFILES" => "C:\\Program Files",
          "PROGRAMFILES(X86)" => "C:\\Program Files (x86)",
          "WINDIR"       => "C:\\Windows",
          "SYSTEMROOT"   => "C:\\Windows",
          "COMSPEC"      => "C:\\Windows\\system32\\cmd.exe",
          "PATH"         => "C:\\Windows;C:\\Windows\\system32",
        }
        get_env_w = lambda do |machine, args|
          name = machine.read_wstring(args[0])
          val  = env_overrides[name.upcase] || ENV[name] || ""
          buf  = args[1] & 0xFFFF_FFFF
          cch  = args[2] & 0xFFFF_FFFF

          encoded = +"".b
          val.each_codepoint { |c| encoded << [c & 0xFFFF].pack("v") }
          needed = encoded.bytesize / 2 + 1 # include null terminator
          ret = if buf == 0 || cch < needed
                  needed
                else
                  machine.memory.write(buf, encoded)
                  machine.memory.write_u16(buf + encoded.bytesize, 0)
                  needed - 1
                end
          warn format("[GetEnvironmentVariableW] %s -> %s (buf=0x%x cch=%d ret=%d)",
                       name.inspect, val.inspect, buf, cch, ret)
          ret
        end
        dispatcher.install_handler("kernel32.dll", "GetEnvironmentVariableW", args: 3, &get_env_w)
        dispatcher.install_handler("kernel32.dll", "GetTempPathW", args: 2) do |machine, args|
          cch = args[0] & 0xFFFF_FFFF
          buf = args[1] & 0xFFFF_FFFF
          val = "C:\\Temp\\"
          encoded = +"".b
          val.each_codepoint { |c| encoded << [c & 0xFFFF].pack("v") }
          needed = encoded.bytesize / 2 + 1
          if buf == 0 || cch < needed
            needed
          else
            machine.memory.write(buf, encoded)
            machine.memory.write_u16(buf + encoded.bytesize, 0)
            needed - 1
          end
        end
        dispatcher.install_handler("kernel32.dll", "GetEnvironmentVariableA", args: 3) do |machine, args|
          # ASCII version — read with read_cstring, write ASCII.
          name = machine.read_cstring(args[0])
          val  = env_overrides[name.upcase] || ENV[name] || ""
          buf  = args[1] & 0xFFFF_FFFF
          cch  = args[2] & 0xFFFF_FFFF
          needed = val.bytesize + 1
          if buf == 0 || cch < needed
            needed
          else
            machine.memory.write(buf, val + "\x00")
            needed - 1
          end
        end
        dispatcher.install_handler("kernel32.dll", "GetStartupInfoA", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "GetStartupInfoW", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "SetUnhandledExceptionFilter", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "UnhandledExceptionFilter", args: 1) { |_, _| 1 } # EXCEPTION_EXECUTE_HANDLER
        dispatcher.install_handler("kernel32.dll", "IsDebuggerPresent", args: 0) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "OutputDebugStringA", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "OutputDebugStringW", args: 1) { |_, _| 0 }

        # LoadStringW reads from the parsed resource tree. RT_STRING (type 6)
        # groups strings in blocks of 16 with the resource name = (id/16)+1
        # and the index within the block = id%16. Each string in the block is
        # prefixed by a 16-bit length (in chars), followed by UTF-16 data (no
        # null terminator in the on-disk form).
        # Track recent string loads so empty MessageBoxes can show what the
        # binary was trying to load. We keep the last 16 attempts.
        recent_strings = []

        dispatcher.install_handler("user32.dll", "LoadStringW", args: 4) do |machine, args|
          uid = args[1] & 0xFFFF
          buf = args[2]
          cch = args[3] & 0xFFFF_FFFF

          block_id  = (uid / 16) + 1
          inside    = uid % 16
          resource  = machine.image.find_resource(6, block_id)
          next 0 unless resource

          base = machine.image.image_base + resource[:data_rva]
          pos  = base
          inside.times do
            length = machine.memory.read_u16(pos)
            pos += 2 + length * 2
          end
          length = machine.memory.read_u16(pos)
          pos += 2

          # Record the (id, decoded text) for later context display.
          if length > 0
            preview = machine.memory.read(pos, length * 2)
                              .force_encoding("UTF-16LE").encode("UTF-8")
            recent_strings << [uid, preview]
            recent_strings.shift if recent_strings.size > 16
          end

          if buf == 0 || cch == 0
            length
          else
            copy = [length, cch - 1].min
            machine.memory.write(buf, machine.memory.read(pos, copy * 2)) if copy > 0
            machine.memory.write_u16(buf + copy * 2, 0)
            copy
          end
        end

        # Make the dialog renderer able to consult recent_strings.
        machine_recent_strings_proc = -> { recent_strings.dup }

        # Log MessageBoxW text so we can see what the installer is trying to
        # tell the (absent) user. Returns IDOK (1) so callers proceed.
        # CharNextW/A advance one (wide)character; the default "return 0"
        # stub makes the caller's pointer go null and then crash.
        dispatcher.install_handler("user32.dll", "CharNextW", args: 1) do |machine, args|
          ptr = args[0] & 0xFFFF_FFFF
          next 0 if ptr == 0
          # Stop advancing past the NUL terminator (Windows semantics).
          machine.memory.read_u16(ptr) == 0 ? ptr : ptr + 2
        end
        dispatcher.install_handler("user32.dll", "CharNextA", args: 1) do |machine, args|
          ptr = args[0] & 0xFFFF_FFFF
          next 0 if ptr == 0
          machine.memory.read_u8(ptr) == 0 ? ptr : ptr + 1
        end
        dispatcher.install_handler("user32.dll", "CharUpperBuffW", args: 2) { |_, args| args[1] & 0xFFFF_FFFF }
        dispatcher.install_handler("user32.dll", "CharLowerBuffW", args: 2) { |_, args| args[1] & 0xFFFF_FFFF }

        # Render the guest's MessageBox as a real ASCII dialog on stderr so
        # we can see what the installer is saying. Returns the primary-button
        # ID for the given MB_* style.
        render_msgbox = lambda do |machine, args, wide:|
          text = wide ? machine.read_wstring(args[1]) : machine.read_cstring(args[1])
          cap  = wide ? machine.read_wstring(args[2]) : machine.read_cstring(args[2])
          type = args[3] & 0xFFFF_FFFF

          buttons = case type & 0x0F
                    when 0    then ["OK"]
                    when 1    then ["OK", "Cancel"]
                    when 2    then ["Abort", "Retry", "Ignore"]
                    when 3    then ["Yes", "No", "Cancel"]
                    when 4    then ["Yes", "No"]
                    when 5    then ["Retry", "Cancel"]
                    when 6    then ["Cancel", "Try Again", "Continue"]
                    else ["OK"]
                    end
          icon = case (type >> 4) & 0xF
                 when 1 then "[!]"
                 when 2 then "[?]"
                 when 3 then "[X]"
                 when 4 then "[i]"
                 else "[ ]"
                 end

          title_line = cap.empty? ? "(no caption)" : cap
          body_lines = text.empty? ? ["(empty body)"] : text.split(/\r?\n/)

          # If the body is empty, add a context block: the binary couldn't
          # populate this dialog because its Delphi RTL resource-string
          # table wasn't initialized. Show recent LoadStringW lookups so
          # the user can see what kinds of messages this binary uses.
          context_lines = []
          if text.empty?
            recent = machine_recent_strings_proc.call.last(6)
            unless recent.empty?
              context_lines << ""
              context_lines << "Recent strings the binary loaded (LoadStringW):"
              recent.each do |uid, preview|
                trimmed = preview.length > 60 ? preview[0, 57] + "..." : preview
                context_lines << format("  [%5d]  %s", uid, trimmed)
              end
            end
          end

          all_body = body_lines + context_lines
          width = [title_line.length, *all_body.map(&:length), buttons.join("  ").length + 8].max + 4
          warn "+" + "-" * (width + 2) + "+"
          warn "| #{icon} #{title_line.ljust(width - 4)} |"
          warn "+" + "-" * (width + 2) + "+"
          all_body.each { |line| warn "|  #{line.ljust(width)} |" }
          warn "|  #{(buttons.join("  ")).ljust(width)} |"
          warn "+" + "-" * (width + 2) + "+"

          # Default to the "proceed" answer (OK / Yes / Continue / Retry).
          # Real installers usually mean those as "use default and continue";
          # picking the destructive answer ends the run earlier with less
          # diagnostic value.
          id = case type & 0x0F
               when 0, 1 then 1   # IDOK
               when 2    then 4   # IDRETRY
               when 3, 4 then 6   # IDYES
               when 5    then 4   # IDRETRY
               when 6    then 11  # IDCONTINUE
               else 1
               end
          # show what we actually returned, not just the first button
          name_for = {1 => "OK", 2 => "Cancel", 3 => "Abort", 4 => "Retry",
                      5 => "Ignore", 6 => "Yes", 7 => "No", 10 => "TryAgain",
                      11 => "Continue"}
          warn "  (auto-replied #{name_for[id] || id.to_s})"
          warn ""
          id
        end

        dispatcher.install_handler("user32.dll", "MessageBoxW", args: 4) do |machine, args|
          render_msgbox.call(machine, args, wide: true)
        end
        dispatcher.install_handler("user32.dll", "MessageBoxA", args: 4) do |machine, args|
          render_msgbox.call(machine, args, wide: false)
        end

        dispatcher.install_handler("kernel32.dll", "GetSystemInfo", args: 1) do |machine, args|
          ptr = args[0]
          next 0 if ptr == 0

          # SYSTEM_INFO has identical layout for 32 and 64-bit guests for the
          # initial DWORD union and PageSize. Pointer fields differ in width,
          # but our guests won't actually use them.
          machine.memory.write_u32(ptr + 0x00, 0)            # wProcessorArchitecture = INTEL, wReserved = 0
          machine.memory.write_u32(ptr + 0x04, 0x1000)       # dwPageSize
          # Skip the LPVOID pair (we don't compute real bounds). Zero is OK.
          machine.memory.write_u32(ptr + (machine.mode == 64 ? 0x20 : 0x14), 1) # dwNumberOfProcessors
          0
        end
        dispatcher.install_handler("kernel32.dll", "GetNativeSystemInfo", args: 1) do |machine, args|
          machine.dispatcher.thunks # no-op to keep linter calm
          ptr = args[0]
          next 0 if ptr == 0

          machine.memory.write_u32(ptr + 0x00, 9) # AMD64
          machine.memory.write_u32(ptr + 0x04, 0x1000)
          0
        end
      end
    end
  end
end
