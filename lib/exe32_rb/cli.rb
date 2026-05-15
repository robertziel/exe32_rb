# frozen_string_literal: true

require "optparse"

module Exe32Rb
  # Command-line frontend for the i386 / PE32 emulator. Rejects PE32+
  # binaries up front; the loader still parses them, but execution is
  # locked to 32-bit mode.
  class CLI
    USAGE = <<~TXT
      usage: exe32_rb <command> [options]

      commands:
        dump    <file.exe>           print PE headers, sections, and imports
        run     <file.exe>           emulate the binary (i386 only)
        disasm  <file.exe>           disassemble N instructions from entry
        hello   <out.exe>            write a minimal hello-world PE32
        version                      print exe32_rb version

      run options:
        --trace                      echo every instruction + API call
        --stub-missing               install permissive stubs for unbound APIs
        --call-stub=ADDR[=RETVAL]    redirect call-through-pointer at ADDR to a
                                     stub that returns RETVAL (default 0)
                                     e.g. --call-stub=0x412740=0  (repeatable)
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
      when "dump"    then cmd_dump
      when "run"     then cmd_run
      when "disasm"  then cmd_disasm
      when "hello"   then cmd_hello
      when "version" then puts(Exe32Rb::VERSION); 0
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
      opts = {trace: false, stub_missing: false, call_stubs: []}
      OptionParser.new do |o|
        o.on("--trace")          { opts[:trace] = true }
        o.on("--stub-missing")   { opts[:stub_missing] = true }
        o.on("--max-steps N", Integer) { |n| opts[:max_steps] = n }
        o.on("--call-stub=ADDR[=RETVAL]", String) do |s|
          addr_str, ret_str = s.split("=", 2)
          opts[:call_stubs] << [Integer(addr_str), ret_str ? Integer(ret_str) : 0]
        end
      end.parse!(@argv)
      path = @argv.shift or abort("run requires a file path")

      image = load_image(path)
      machine = Exe32Rb::Emulator::Machine.new(image, trace: opts[:trace]).configure
      install_stub_missing(machine) if opts[:stub_missing]
      install_call_stubs(machine, opts[:call_stubs])

      kw = {}
      kw[:max_steps] = opts[:max_steps] if opts[:max_steps]
      machine.run(**kw)
      [(machine.exit_code || 0) & 0xFF, 255].min
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
