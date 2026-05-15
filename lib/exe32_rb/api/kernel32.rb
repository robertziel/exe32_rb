# frozen_string_literal: true

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
          File.delete(machine.read_wstring(args[0]))
          1
        rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR
          0
        end

        dispatcher.install_handler("kernel32.dll", "GetFileAttributesW", args: 1) do |machine, args|
          path = machine.read_wstring(args[0])
          if !File.exist?(path) then 0xFFFF_FFFF
          elsif File.directory?(path) then 0x10
          else 0x80
          end
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

        dispatcher.install_handler("kernel32.dll", "RaiseException", args: 4) do |_machine, args|
          code = args[0] & 0xFFFF_FFFF
          warn format("[RaiseException] code=0x%08X flags=0x%X (no SEH support; halting)",
                      code, args[1] & 0xFFFF_FFFF)
          raise Emulator::Executor::HaltSignal.new(code)
        end

        dispatcher.install_handler("kernel32.dll", "GetLastError", args: 0) do |_machine, _args|
          0
        end

        dispatcher.install_handler("kernel32.dll", "SetLastError", args: 1) do |_machine, _args|
          0
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

        dispatcher.install_handler("kernel32.dll", "GetVersion",         args: 0) { |_, _| 0x0023_0A00 } # Win10 6.0 build 10 form
        dispatcher.install_handler("kernel32.dll", "GetVersionExA",      args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetVersionExW",      args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetTickCount",       args: 0) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "GetCurrentProcess",  args: 0) { |_, _| 0xFFFF_FFFF }
        dispatcher.install_handler("kernel32.dll", "GetCurrentProcessId", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetCurrentThreadId", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "IsProcessorFeaturePresent", args: 1) { |_, _| 0 }
        dispatcher.install_handler("kernel32.dll", "QueryPerformanceCounter", args: 1) do |machine, args|
          machine.memory.write_u64(args[0], 0) if args[0] != 0
          1
        end
        dispatcher.install_handler("kernel32.dll", "QueryPerformanceFrequency", args: 1) do |machine, args|
          machine.memory.write_u64(args[0], 1_000_000) if args[0] != 0
          1
        end
        dispatcher.install_handler("kernel32.dll", "GetSystemTimeAsFileTime", args: 1) do |machine, args|
          machine.memory.write_u64(args[0], 0) if args[0] != 0
          0
        end

        # Heap stubs (bump allocator hosted in scratch — fine for short-lived
        # programs; not a real heap).
        dispatcher.install_handler("kernel32.dll", "HeapCreate", args: 3) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapDestroy", args: 1) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "GetProcessHeap", args: 0) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapAlloc", args: 3) do |machine, args|
          size = args[2] & 0xFFFF_FFFF
          machine.scratch_alloc(size, zero: (args[1] & 0x8) != 0)
        end
        dispatcher.install_handler("kernel32.dll", "HeapFree", args: 3) { |_, _| 1 }
        dispatcher.install_handler("kernel32.dll", "HeapSize", args: 3) { |_, _| 0 }

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
          machine.scratch_strz_w("")
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

          if buf == 0 || cch == 0
            length
          else
            copy = [length, cch - 1].min
            machine.memory.write(buf, machine.memory.read(pos, copy * 2)) if copy > 0
            machine.memory.write_u16(buf + copy * 2, 0)
            copy
          end
        end

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

        dispatcher.install_handler("user32.dll", "MessageBoxW", args: 4) do |machine, args|
          text = machine.read_wstring(args[1])
          cap  = machine.read_wstring(args[2])
          type = args[3] & 0xFFFF_FFFF
          warn format("[MessageBoxW] caption=%s text=%s type=0x%x", cap.inspect, text.inspect, type)
          # Return the "primary" button for each MB_* style:
          #   MB_OK            -> IDOK (1)
          #   MB_OKCANCEL      -> IDOK (1)
          #   MB_ABORTRETRYIGNORE -> IDRETRY (4)
          #   MB_YESNOCANCEL   -> IDYES (6)
          #   MB_YESNO         -> IDYES (6)
          #   MB_RETRYCANCEL   -> IDRETRY (4)
          case type & 0x0F
          when 0, 1 then 1
          when 2    then 4
          when 3, 4 then 6
          when 5    then 4
          else 1
          end
        end
        dispatcher.install_handler("user32.dll", "MessageBoxA", args: 4) do |machine, args|
          text = machine.read_cstring(args[1])
          cap  = machine.read_cstring(args[2])
          warn format("[MessageBoxA] caption=%s text=%s", cap.inspect, text.inspect)
          1
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
