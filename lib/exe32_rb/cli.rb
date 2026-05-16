# frozen_string_literal: true

require "optparse"
require "set"

module Exe32Rb
  # Command-line frontend for the i386 / PE32 emulator. Rejects PE32+
  # binaries up front; the loader still parses them, but execution is
  # locked to 32-bit mode.
  class CLI
    USAGE = <<~TXT
      usage: exe32_rb <command> [options]

      commands:
        dump      <file.exe>         print PE headers, sections, and imports
        run       <file.exe>         emulate the binary (i386 only)
        debug     <file.exe>         interactive step-debugger (step/break/registers/memory)
        visualize <file.exe>         live Ruby2D window showing regs/disasm/stack/log
        disasm    <file.exe>         disassemble N instructions from entry
        strings   <file.exe>         list all UI strings (RT_STRING) embedded in the binary
        hello     <out.exe>          write a minimal hello-world PE32
        version                      print exe32_rb version

      run options:
        --trace                      echo every instruction + API call
        --stub-missing               install permissive stubs for unbound APIs
        --call-stub=ADDR[=RETVAL]    redirect call-through-pointer at ADDR to a
                                     stub that returns RETVAL (default 0)
                                     e.g. --call-stub=0x412740=0  (repeatable)
        --patch=ADDR=HEX             overwrite guest memory at ADDR with HEX bytes
                                     e.g. --patch=0x401C7C=33C0C3   (repeatable)
        --watch=ADDR                 log every write that touches ADDR (repeatable)
        --break=ADDR                 log register state when EIP hits ADDR (repeatable)
        --delphi-memmgr=ADDR         replace the Delphi TMemoryManager record at ADDR
                                     with Ruby handlers (GetMem/FreeMem/Realloc...)
                                     find ADDR by scanning .data for a run of 6
                                     consecutive function pointers in .text
        --winfs[=DIR]                map guest C:\... paths into a sandbox dir on
                                     host (default: <TMPDIR>/exe32_rb_root). All
                                     CreateFile/Directory/Delete calls translate.
        --lenient                    unmapped reads return 0, writes are dropped
        --jit                        enable basic-block JIT (~25% faster, mutually
                                     exclusive with --trace)
        --gui                        run emulator in a worker thread and open a real
                                     Ruby2D window for the guest. CreateWindowExW /
                                     ShowWindow / GetMessageW are bound to user32
                                     handlers that drive the window.
                                     (lets buggy guest code stumble forward)
        --max-steps N                cap the step count

      disasm options:
        -n, --limit N                number of instructions to print (default 16)
    TXT

    def initialize(argv)
      @argv = argv.dup
    end

    def run
      command = @argv.shift
      case command
      when "dump"      then cmd_dump
      when "run"       then cmd_run
      when "debug"     then cmd_debug
      when "visualize" then cmd_visualize
      when "disasm"    then cmd_disasm
      when "strings"   then cmd_strings
      when "hello"     then cmd_hello
      when "version"   then puts(Exe32Rb::VERSION); 0
      when nil, "-h", "--help" then puts(USAGE); 0
      else
        warn "unknown command: #{command}"
        warn USAGE
        2
      end
    rescue Exe32Rb::Error, ArgumentError => e
      warn "exe32_rb: #{e.message}"
      1
    end

    private

    def cmd_dump
      path = @argv.shift or abort("dump requires a file path")
      image = load_image(path)
      print_header(image)
      print_sections(image)
      print_imports(image)
      0
    end

    def cmd_run
      opts = {trace: false, stub_missing: false, call_stubs: [], patches: []}
      OptionParser.new do |o|
        o.on("--trace")          { opts[:trace] = true }
        o.on("--stub-missing")   { opts[:stub_missing] = true }
        o.on("--max-steps N", Integer) { |n| opts[:max_steps] = n }
        o.on("--call-stub=ADDR[=RETVAL]", String) do |s|
          addr_str, ret_str = s.split("=", 2)
          opts[:call_stubs] << [Integer(addr_str), ret_str ? Integer(ret_str) : 0]
        end
        o.on("--patch=ADDR=HEX", String) do |s|
          addr_str, hex = s.split("=", 2)
          opts[:patches] << [Integer(addr_str), [hex].pack("H*")]
        end
        o.on("--watch=ADDR", String) { |s| (opts[:watches] ||= []) << Integer(s) }
        o.on("--break=ADDR", String) { |s| (opts[:breaks]  ||= []) << Integer(s) }
        o.on("--delphi-memmgr=ADDR", String) { |s| opts[:delphi_memmgr] = Integer(s) }
        o.on("--winfs[=DIR]", String) { |s| opts[:winfs] = s || :default }
        o.on("--com") { opts[:com] = true }
        o.on("--load-dlls") { opts[:load_dlls] = true }
        o.on("--dll-search=DIR", String) { |s| (opts[:dll_search] ||= []) << s }
        o.on("--directdraw") { opts[:directdraw] = true }
        o.on("--lenient") { opts[:lenient] = true }
        o.on("--jit") { opts[:jit] = true }
        o.on("--gui") { opts[:gui] = true }
      end.parse!(@argv)
      path = @argv.shift or abort("run requires a file path")

      image = load_image(path)
      machine = Exe32Rb::Emulator::Machine.new(image, trace: opts[:trace]).configure
      machine.enable_jit if opts[:jit]
      machine.memory.lenient = true if opts[:lenient]
      install_stub_missing(machine) if opts[:stub_missing]
      install_call_stubs(machine, opts[:call_stubs])
      apply_patches(machine, opts[:patches])
      install_watchpoints(machine, opts[:watches] || [])
      install_breakpoints(machine, opts[:breaks] || [])
      if opts[:delphi_memmgr]
        require "exe32_rb/api/delphi_memmgr"
        Exe32Rb::Api::DelphiMemMgr.install(machine, opts[:delphi_memmgr])
      end
      if opts[:winfs]
        require "exe32_rb/api/win_fs"
        if opts[:winfs] == :default
          Exe32Rb::Api::WinFS.install(machine)
        else
          Exe32Rb::Api::WinFS.install(machine, root: opts[:winfs])
        end
      end
      if opts[:com]
        require "exe32_rb/api/com"
        Exe32Rb::Api::Com.install(machine)
      end
      if opts[:load_dlls]
        require "exe32_rb/api/dll_loader"
        Exe32Rb::Api::DllLoaderInstall.install(machine, search_paths: opts[:dll_search] || [])
      end
      if opts[:directdraw]
        require "exe32_rb/api/directdraw"
        Exe32Rb::Api::DirectDraw.install(machine)
      end
      if opts[:gui]
        require "exe32_rb/api/user32"
        require "exe32_rb/api/gdi32"
        Exe32Rb::Api::User32.install(machine)
        Exe32Rb::Api::Gdi32.install(machine)
      end

      kw = {}
      kw[:max_steps] = opts[:max_steps] if opts[:max_steps]

      if opts[:gui]
        run_with_gui(machine, **kw)
      else
        machine.run(**kw)
        [(machine.exit_code || 0) & 0xFF, 255].min
      end
    end

    # Run the emulator on a worker thread, then turn the main thread
    # over to Ruby2D's event loop. The first window the guest creates
    # becomes the visible OS window; closing it tears the emulator down.
    def run_with_gui(machine, **kw)
      require "exe32_rb/gui"
      gui = Exe32Rb::GUI.instance
      exit_status = nil

      emu = Thread.new do
        Thread.current.report_on_exception = true
        begin
          # Wait until run_event_loop has actually called Ruby2D::Window.show
          # so that early GUI calls (MessageBoxW from main(), etc.) see a
          # live window and don't fall through to the headless path.
          gui.wait_until_ready
          machine.run(**kw)
          exit_status = [(machine.exit_code || 0) & 0xFF, 255].min
        rescue => e
          warn "[gui] emulator thread crashed: #{e.class}: #{e.message}"
          warn e.backtrace.first(5).join("\n")
          exit_status = 1
        ensure
          gui.request_quit
        end
      end

      # Discover the eventual window title once the guest creates a
      # window; until then, show a placeholder title.
      gui.run_event_loop(title: "exe32_rb — running #{File.basename(machine.image.path)}",
                          width: 800, height: 600)

      emu.join(2) # give the worker a moment to wind down
      emu.kill if emu.alive?
      exit_status || 0
    end

    # Instruction breakpoints — log register state every time EIP hits ADDR.
    # Wrap Machine#step so we get a per-tick check before the decoder runs.
    def install_breakpoints(machine, addresses)
      return if addresses.empty?

      addr_set = Set.new(addresses)
      hits = Hash.new(0)
      original_step = machine.method(:step)
      machine.define_singleton_method(:step) do
        rip = cpu.rip
        if addr_set.include?(rip)
          hits[rip] += 1
          r = cpu.registers
          warn format("[break] 0x%08X hit=%d  eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X esi=0x%08X edi=0x%08X ebp=0x%08X esp=0x%08X",
                       rip, hits[rip], r.read32(0), r.read32(3), r.read32(1),
                       r.read32(2), r.read32(6), r.read32(7), r.read32(5), r.read32(4))
        end
        original_step.call
      end
    end

    # Memory watchpoints: log every write that intersects a watched address.
    # We hook Memory#write_callback (already exists for icache invalidation)
    # and report addr + the new value + current rip.
    def install_watchpoints(machine, addresses)
      return if addresses.empty?

      addresses.each { |a| warn format("[watch] 0x%08X", a) }
      previous = machine.memory.write_callback
      machine.memory.write_callback = lambda do |addr, size|
        previous&.call(addr, size)
        addresses.each do |watch|
          if watch >= addr && watch < addr + size
            new = machine.memory.read_u32(watch & ~3)
            r = machine.cpu.registers
            warn format("[watch] 0x%08X <- 0x%08X  (rip=0x%08X step=%d)\n" \
                        "                          eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X\n" \
                        "                          esi=0x%08X edi=0x%08X ebp=0x%08X esp=0x%08X",
                         watch, new, machine.cpu.rip, machine.steps_executed,
                         r.read32(0), r.read32(3), r.read32(1), r.read32(2),
                         r.read32(6), r.read32(7), r.read32(5), r.read32(4))
          end
        end
      end
    end

    def apply_patches(machine, patches)
      patches.each do |addr, bytes|
        machine.memory.write(addr, bytes)
        warn format("[patch] wrote %d bytes at 0x%x", bytes.bytesize, addr)
      end
    end

    def install_call_stubs(machine, specs)
      specs.each do |(addr, retval)|
        machine.dispatcher.install_call_stub(addr) { retval }
        warn format("[call-stub] 0x%x will return %d", addr, retval)
      end
    end

    def cmd_disasm
      limit = 16
      OptionParser.new do |o|
        o.on("-n N", "--limit N", Integer) { |n| limit = n }
      end.parse!(@argv)
      path = @argv.shift or abort("disasm requires a file path")

      image = load_image(path)
      machine = Exe32Rb::Emulator::Machine.new(image).configure
      rip = image.entry_point
      limit.times do
        instr = machine.decoder.decode(rip)
        puts instr.to_s
        rip = (rip + instr.length) & machine.cpu.address_mask
      end
      0
    end

    # Drop into the Ruby2D live visualizer window. Requires the ruby2d gem
    # (`gem install ruby2d`).
    def cmd_visualize
      opts = {stub_missing: false, call_stubs: []}
      OptionParser.new do |o|
        o.on("--stub-missing")  { opts[:stub_missing] = true }
        o.on("--call-stub=ADDR[=RETVAL]", String) do |s|
          addr_str, ret_str = s.split("=", 2)
          opts[:call_stubs] << [Integer(addr_str), ret_str ? Integer(ret_str) : 0]
        end
      end.parse!(@argv)
      path = @argv.shift or abort("visualize requires a file path")

      image = load_image(path)
      machine = Exe32Rb::Emulator::Machine.new(image).configure
      install_stub_missing(machine) if opts[:stub_missing]
      install_call_stubs(machine, opts[:call_stubs])
      require "exe32_rb/visualizer"
      Exe32Rb::Visualizer.new(machine).run
      0
    end

    # Drop into the interactive step-debugger REPL.
    def cmd_debug
      opts = {stub_missing: false, call_stubs: []}
      OptionParser.new do |o|
        o.on("--stub-missing")  { opts[:stub_missing] = true }
        o.on("--call-stub=ADDR[=RETVAL]", String) do |s|
          addr_str, ret_str = s.split("=", 2)
          opts[:call_stubs] << [Integer(addr_str), ret_str ? Integer(ret_str) : 0]
        end
      end.parse!(@argv)
      path = @argv.shift or abort("debug requires a file path")

      image = load_image(path)
      machine = Exe32Rb::Emulator::Machine.new(image).configure
      install_stub_missing(machine) if opts[:stub_missing]
      install_call_stubs(machine, opts[:call_stubs])
      Exe32Rb::Debugger.new(machine).run
      0
    end

    # Dump every UTF-16 string in the binary's RT_STRING resource table.
    # No emulation required — pure read of the parsed PE resource tree.
    def cmd_strings
      path = @argv.shift or abort("strings requires a file path")
      image = load_image(path)
      string_tree = image.resources[6] # RT_STRING
      unless string_tree
        puts "(no RT_STRING resource)"
        return 0
      end

      machine = Exe32Rb::Emulator::Machine.new(image).configure
      string_tree.keys.sort.each do |block_id|
        next unless block_id.is_a?(Integer)

        resource = image.find_resource(6, block_id)
        next unless resource

        base = image.image_base + resource[:data_rva]
        pos  = base
        16.times do |i|
          length = machine.memory.read_u16(pos)
          pos += 2
          if length > 0
            bytes = machine.memory.read(pos, length * 2)
            text  = bytes.force_encoding("UTF-16LE").encode("UTF-8")
            uid   = (block_id - 1) * 16 + i
            puts format("  [id %5d]  %s", uid, text)
          end
          pos += length * 2
        end
      end
      0
    end

    def cmd_hello
      path = @argv.shift or abort("hello requires an output path")
      Exe32Rb::Samples::HelloWorld.write(path)
      puts "wrote #{path} (#{File.size(path)} bytes, i386 / PE32)"
      0
    end

    def load_image(path)
      image = Exe32Rb::PE::Loader.load(path)
      unless image.bitness == 32
        raise Exe32Rb::Error,
              "exe32_rb only supports PE32/i386; this image is " \
              "#{image.bitness}-bit #{Exe32Rb::PE::Constants.machine_name(image.machine)}"
      end

      image
    end

    def install_stub_missing(machine)
      Exe32Rb::Api::Signatures.install_default_stubs(machine.dispatcher)
      seen = Hash.new(0)
      machine.dispatcher.install_missing_handler(args: 0) { nil }
      original = machine.dispatcher.method(:invoke)
      machine.dispatcher.define_singleton_method(:invoke) do |address, mach|
        imp = thunks[address]
        unless installed?(imp.dll, imp.name || "##{imp.ordinal}")
          key = imp.display_name
          seen[key] += 1
          warn "[unknown] #{key}" if seen[key] == 1
        end
        original.call(address, mach)
      end
    end

    def print_header(image)
      printf "File:       %s\n", image.path
      printf "Machine:    %s\n", Exe32Rb::PE::Constants.machine_name(image.machine)
      printf "Bitness:    %d-bit\n", image.bitness
      printf "Subsystem:  %s\n", Exe32Rb::PE::Constants.subsystem_name(image.subsystem)
      printf "ImageBase:  0x%08X\n", image.image_base
      printf "EntryPoint: 0x%08X  (RVA 0x%X)\n", image.entry_point, image.entry_point_rva
      printf "SizeOfImage:   0x%X\n", image.size_of_image
      printf "SizeOfHeaders: 0x%X\n", image.size_of_headers
    end

    def print_sections(image)
      puts
      puts "Sections:"
      image.sections.each do |s|
        flags = []
        flags << "code"  if s.characteristics & Exe32Rb::PE::Constants::SCN_CNT_CODE != 0
        flags << "idata" if s.characteristics & Exe32Rb::PE::Constants::SCN_CNT_INITIALIZED_DATA != 0
        flags << "udata" if s.characteristics & Exe32Rb::PE::Constants::SCN_CNT_UNINITIALIZED_DATA != 0
        flags << (s.readable?   ? "r" : "-")
        flags << (s.writable?   ? "w" : "-")
        flags << (s.executable? ? "x" : "-")
        printf "  %-8s  VA 0x%08X  vsize 0x%06X  raw 0x%06X @0x%06X  [%s]\n",
               s.name, s.virtual_address, s.virtual_size, s.size_of_raw_data,
               s.pointer_to_raw_data, flags.join(" ")
      end
    end

    def print_imports(image)
      puts
      puts "Imports:"
      image.imports.group_by(&:dll).each do |dll, imports|
        puts "  #{dll}:"
        imports.each do |imp|
          puts(imp.by_ordinal? ? "    ##{imp.ordinal}" : "    #{imp.name}")
        end
      end
    end

    def abort(message)
      raise Exe32Rb::Error, message
    end
  end
end
