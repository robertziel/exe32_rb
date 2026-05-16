# frozen_string_literal: true

require_relative "test_helper"
require "fileutils"
require "tmpdir"

# Tests for the session's infrastructure additions: SEH dispatch,
# Delphi MemoryManager replacement, WinFS path sandbox, conventions.
class InfrastructureTest < Minitest::Test
  # ----------------------------------------------------------------
  # WinFS path translation
  # ----------------------------------------------------------------

  def test_winfs_translates_drive_paths
    require "exe32_rb/api/win_fs"
    root = "/tmp/test_root"
    assert_equal "/tmp/test_root/C/Temp/foo.txt",
                 Exe32Rb::Api::WinFS.translate(root, "C:\\Temp\\foo.txt")
    assert_equal "/tmp/test_root/D/data.dat",
                 Exe32Rb::Api::WinFS.translate(root, "D:\\data.dat")
  end

  def test_winfs_handles_forward_slashes
    require "exe32_rb/api/win_fs"
    assert_equal "/tmp/test_root/C/foo/bar",
                 Exe32Rb::Api::WinFS.translate("/tmp/test_root", "C:/foo/bar")
  end

  def test_winfs_strips_unc_prefix
    require "exe32_rb/api/win_fs"
    assert_equal "/tmp/test_root/C/path",
                 Exe32Rb::Api::WinFS.translate("/tmp/test_root", "\\\\?\\C:\\path")
  end

  def test_winfs_routes_relative_into_synthetic_temp
    require "exe32_rb/api/win_fs"
    assert_equal "/tmp/test_root/C/Temp/relative.txt",
                 Exe32Rb::Api::WinFS.translate("/tmp/test_root", "relative.txt")
  end

  def test_winfs_returns_path_unchanged_when_root_is_nil
    require "exe32_rb/api/win_fs"
    assert_equal "C:\\foo", Exe32Rb::Api::WinFS.translate(nil, "C:\\foo")
  end

  # ----------------------------------------------------------------
  # DelphiRegister calling convention
  # ----------------------------------------------------------------

  def test_delphi_register_convention_reads_args_from_eax_edx_ecx
    require "exe32_rb/api/conventions"
    machine = mini_machine_with_cpu(mode: 32)
    machine.cpu.registers.write32(0, 0xAAAA) # eax
    machine.cpu.registers.write32(2, 0xBBBB) # edx
    machine.cpu.registers.write32(1, 0xCCCC) # ecx
    conv = Exe32Rb::Api::Conventions::DelphiRegister.new

    assert_equal [0xAAAA], conv.read_args(machine, 1)
    assert_equal [0xAAAA, 0xBBBB], conv.read_args(machine, 2)
    assert_equal [0xAAAA, 0xBBBB, 0xCCCC], conv.read_args(machine, 3)
  end

  def test_delphi_register_convention_writes_return_to_eax
    require "exe32_rb/api/conventions"
    machine = mini_machine_with_cpu(mode: 32)
    conv = Exe32Rb::Api::Conventions::DelphiRegister.new
    conv.return_value(machine, 0xDEADBEEF)
    assert_equal 0xDEADBEEF, machine.cpu.registers.read32(0)
  end

  # ----------------------------------------------------------------
  # Dispatcher.install_thunk
  # ----------------------------------------------------------------

  def test_dispatcher_install_thunk_returns_callable_address
    mem = Exe32Rb::Emulator::Memory.new
    mem.map(0x6000_0000, 0x1000, name: "thunks")
    dispatcher = Exe32Rb::Api::Dispatcher.new(mem, mode: 32)

    addr = dispatcher.install_thunk("test_handler", args: 0) { 42 }
    assert addr > 0, "thunk address should be non-zero"
    assert dispatcher.thunk?(addr), "address should register as a thunk"
  end

  # ----------------------------------------------------------------
  # Hello world still works with all new APIs loaded
  # ----------------------------------------------------------------

  def test_hello_world_unaffected_by_new_apis
    Dir.mktmpdir do |dir|
      path = File.join(dir, "hello.exe")
      Exe32Rb::Samples::HelloWorld.write(path)
      machine = Exe32Rb::Machine.from_path(path).configure
      output = capture_stdout { machine.run }
      assert_equal "Hello, world!\n", output
    end
  end

  # ----------------------------------------------------------------
  # SEH dispatch end-to-end
  # ----------------------------------------------------------------

  def test_seh_dispatch_redirects_eip_to_handler_on_fault
    # Build a tiny synthetic Machine with a tiny "binary" image and
    # a single SEH frame installed at FS:[0]. Trigger a fault, watch
    # rip jump to the handler we installed.
    machine = Exe32Rb::Emulator::Machine.new(synth_image)
    machine.send(:map_image_for_test) if machine.respond_to?(:map_image_for_test)
    # Use the regular configure path: we need stack, scratch, TIB, etc.
    machine.configure

    # Reserve a thunk address in code that will be our SEH handler.
    handler_addr = 0x00500000
    machine.memory.map(handler_addr & ~0xFFF, 0x1000, name: "handler")
    # Plant a single RET at handler_addr so the handler immediately
    # returns (eax = whatever the test sets; we'll set to 0).
    machine.memory.write(handler_addr, [0x33, 0xC0, 0xC3].pack("C*")) # xor eax, eax; ret

    # Install an SEH frame on the stack: { prev, handler }
    frame_addr = machine.cpu.rsp - 8
    machine.memory.write_u32(frame_addr,     0xFFFF_FFFF) # prev = end of chain
    machine.memory.write_u32(frame_addr + 4, handler_addr)
    machine.memory.write_u32(machine.cpu.fs_base, frame_addr)

    # Trigger an exception dispatch.
    ok = machine.raise_guest_exception(0xC0000005, [0x00000000])
    assert ok, "raise_guest_exception should succeed when chain is non-empty"
    assert_equal handler_addr, machine.cpu.rip, "EIP should jump to handler"
  end

  def test_seh_dispatch_returns_false_when_chain_is_empty
    machine = Exe32Rb::Emulator::Machine.new(synth_image)
    machine.configure
    # FS:[0] is initialized to 0xFFFFFFFF by configure
    refute machine.raise_guest_exception(0xC0000005)
  end

  # ----------------------------------------------------------------
  # Memory#write_callback fires
  # ----------------------------------------------------------------

  # ----------------------------------------------------------------
  # COM stub framework
  # ----------------------------------------------------------------

  def test_com_get_or_create_object_returns_object_with_vtable
    require "exe32_rb/api/com"
    machine = Exe32Rb::Emulator::Machine.new(synth_image)
    machine.configure
    Exe32Rb::Api::Com.install(machine)

    obj = Exe32Rb::Api::Com.get_or_create_object("42424242-4242-4242-4242-424242424242")
    assert obj > 0, "object pointer should be non-zero"
    vtable = machine.memory.read_u32(obj)
    assert vtable > 0, "vtable pointer should be non-zero"

    # Each vtable slot is a thunk address dispatchable by the dispatcher.
    32.times do |slot|
      thunk = machine.memory.read_u32(vtable + slot * 4)
      assert machine.dispatcher.thunk?(thunk),
             "vtable[#{slot}] (0x#{thunk.to_s(16)}) should be a registered thunk"
    end
  end

  def test_com_register_method_overrides_default_stub
    require "exe32_rb/api/com"
    machine = Exe32Rb::Emulator::Machine.new(synth_image)
    machine.configure
    Exe32Rb::Api::Com.install(machine)

    iid = "ABCDABCD-1234-5678-9ABC-DEF012345678"
    captured = []
    Exe32Rb::Api::Com.register_method(iid, 7, "DoSomething", args: 2) do |_m, args|
      captured << args.dup
      0
    end

    obj = Exe32Rb::Api::Com.get_or_create_object(iid)
    vtable = machine.memory.read_u32(obj)
    thunk = machine.memory.read_u32(vtable + 7 * 4)

    # Simulate __stdcall: push `this`, arg1, arg2 then a return address;
    # the dispatcher's read_args pulls args from [esp+4..]
    machine.cpu.push32(machine.memory, 0xCAFE)     # arg2
    machine.cpu.push32(machine.memory, 0xBEEF)     # arg1
    machine.cpu.push32(machine.memory, obj)        # `this`
    machine.cpu.push32(machine.memory, 0x12345)    # return addr
    machine.dispatcher.invoke(thunk, machine)
    assert_equal [[0xBEEF, 0xCAFE]], captured
  end

  # ----------------------------------------------------------------
  # DLL loader (synthetic DLL)
  # ----------------------------------------------------------------

  def test_dll_loader_parses_synthetic_dll_exports
    require "exe32_rb/api/dll_loader"
    Dir.mktmpdir do |dir|
      dll_path = File.join(dir, "test.dll")
      File.binwrite(dll_path, build_synth_dll_with_export("foo", 0x12345))

      machine = Exe32Rb::Emulator::Machine.new(synth_image)
      machine.configure
      loader = Exe32Rb::Api::DllLoader.new(machine)

      base = loader.load(dll_path)
      assert base > 0, "load should return non-zero base"
      assert_equal base + 0x12345, loader.get_proc_address(base, "foo")
      assert_equal 0, loader.get_proc_address(base, "nonexistent")
    end
  end

  # ----------------------------------------------------------------
  # DirectDraw bridge
  # ----------------------------------------------------------------

  def test_directdraw_creates_surface_and_framebuffer
    require "exe32_rb/api/directdraw"
    machine = Exe32Rb::Emulator::Machine.new(synth_image)
    machine.configure
    Exe32Rb::Api::DirectDraw.install(machine)

    # Force the IDirectDraw7 object creation
    ddraw_obj = Exe32Rb::Api::Com.get_or_create_object(
      Exe32Rb::Api::DirectDraw::IID_IDirectDraw7
    )
    assert ddraw_obj > 0

    surface_obj = Exe32Rb::Api::Com.get_or_create_object(
      Exe32Rb::Api::DirectDraw::IID_IDirectDrawSurface7
    )
    assert surface_obj > 0

    fb = Exe32Rb::Api::DirectDraw.framebuffer_addr
    assert fb > 0
    # write a pixel and read it back
    machine.memory.write_u32(fb, 0xFF00FF00)
    assert_equal 0xFF00FF00, machine.memory.read_u32(fb)
  end

  def test_memory_write_callback_fires
    mem = Exe32Rb::Emulator::Memory.new
    mem.map(0x10000, 0x1000, name: "test")
    events = []
    mem.write_callback = ->(addr, size) { events << [addr, size] }

    mem.write_u32(0x10010, 0xDEADBEEF)
    mem.write_u8(0x10020, 0x42)

    assert_equal [[0x10010, 4], [0x10020, 1]], events
  end

  # ----------------------------------------------------------------
  # Interlocked* read-modify-write APIs
  # ----------------------------------------------------------------

  def test_interlocked_exchange_swaps_and_returns_old
    require "exe32_rb/api/kernel32"
    machine = build_kernel32_machine
    addr = 0x10100
    machine.memory.write_u32(addr, 0x1234_5678)

    result = invoke_api(machine, "InterlockedExchange", [addr, 0xABCD_0001])
    assert_equal 0x1234_5678, result, "should return OLD value"
    assert_equal 0xABCD_0001, machine.memory.read_u32(addr)
  end

  def test_interlocked_compare_exchange_swaps_only_on_match
    require "exe32_rb/api/kernel32"
    machine = build_kernel32_machine
    addr = 0x10200
    machine.memory.write_u32(addr, 0x100)

    # Match: swap happens, return old (0x100)
    r1 = invoke_api(machine, "InterlockedCompareExchange",
                    [addr, 0x200, 0x100])
    assert_equal 0x100, r1
    assert_equal 0x200, machine.memory.read_u32(addr)

    # Mismatch: no swap, returns current
    r2 = invoke_api(machine, "InterlockedCompareExchange",
                    [addr, 0x999, 0x000])
    assert_equal 0x200, r2
    assert_equal 0x200, machine.memory.read_u32(addr)
  end

  def test_interlocked_increment_and_decrement
    require "exe32_rb/api/kernel32"
    machine = build_kernel32_machine
    addr = 0x10300
    machine.memory.write_u32(addr, 0x10)

    assert_equal 0x11, invoke_api(machine, "InterlockedIncrement", [addr])
    assert_equal 0x11, machine.memory.read_u32(addr)
    assert_equal 0x10, invoke_api(machine, "InterlockedDecrement", [addr])
    assert_equal 0x10, machine.memory.read_u32(addr)
  end

  def test_create_process_w_populates_process_information
    require "exe32_rb/api/kernel32"
    machine = build_kernel32_machine
    pi_addr = 0x10400
    16.times { |i| machine.memory.write_u8(pi_addr + i, 0) }

    # CreateProcessW has 10 args; args[9] is lpProcessInformation
    args = [0, 0, 0, 0, 0, 0, 0, 0, 0, pi_addr]
    capture_io { invoke_api(machine, "CreateProcessW", args) }

    assert_equal 0x7000_0001, machine.memory.read_u32(pi_addr +  0), "hProcess"
    assert_equal 0x7000_0002, machine.memory.read_u32(pi_addr +  4), "hThread"
    assert_equal 0x1234,      machine.memory.read_u32(pi_addr +  8), "dwPid"
    assert_equal 0x5678,      machine.memory.read_u32(pi_addr + 12), "dwTid"
  end

  private

  # Build a real Machine on a tiny synthetic image with kernel32
  # handlers installed and the dispatcher's missing-handler returning
  # nil. Used by the Interlocked* / CreateProcess tests.
  def build_kernel32_machine
    machine = Exe32Rb::Emulator::Machine.new(synth_image).configure
    machine.dispatcher.install_missing_handler(args: 0) { nil }
    machine.memory.map(0x10000 & ~0xFFF, 0x2000, name: "test-scratch")
    machine
  end

  # Look up a handler by kernel32!<name> key and invoke it with `args`,
  # bypassing convention.read_args/cleanup — handlers receive an args
  # array directly, so we just hand it through.
  def invoke_api(machine, name, args)
    # Dispatcher#key lowercases dll but keeps name as-is.
    key = "kernel32.dll!#{name}"
    entry = machine.dispatcher.instance_variable_get(:@handlers)[key] or
      raise "no handler installed for #{name}"
    entry.handler.call(machine, args)
  end

  # Build a Machine-like fake exposing just .cpu and .registers for
  # convention tests, without going through the real configure() path
  # (which needs a real PE file on disk).
  def mini_machine_with_cpu(mode: 32)
    cpu = Exe32Rb::Emulator::CPU.new(mode: mode)
    cpu.rsp = 0x7000_FF00
    mem = Exe32Rb::Emulator::Memory.new
    mem.map(0x7000_0000, 0x10000, name: "stack")
    Struct.new(:cpu, :memory).new(cpu, mem)
  end

  # A complete, in-memory PE32 image just sufficient for Machine.configure:
  # writes a tiny .text section with a single RET to a temp file so
  # map_image's File.binread doesn't fail.
  def synth_image
    @synth_tmpdir ||= Dir.mktmpdir("synth")
    path = File.join(@synth_tmpdir, "synth.exe")
    File.binwrite(path, build_minimal_pe_bytes) unless File.exist?(path)
    Exe32Rb::PE::Loader.load(path)
  end

  def build_minimal_pe_bytes
    # Build the smallest possible PE32 that the loader accepts and
    # Machine.configure can map. .text has just one byte (a RET).
    section_alignment = 0x1000
    file_alignment    = 0x200
    text_rva   = 0x1000
    header_size = 0x200

    bytes = +"".b
    dos = ("\x00".b * 64); dos[0, 2] = "MZ"; dos[0x3C, 4] = [0x40].pack("V")
    bytes << dos
    bytes << "PE\x00\x00".b
    bytes << [0x014C, 1, 0, 0, 0, 0x00E0, 0x0102].pack("v v V V V v v")

    opt = +"".b
    opt << [0x10B].pack("v") << [1, 0].pack("C C")
    opt << [0x200].pack("V") << [0].pack("V") << [0].pack("V")
    opt << [text_rva].pack("V") << [text_rva].pack("V") << [0].pack("V")
    opt << [0x00400000].pack("V") << [section_alignment].pack("V") << [file_alignment].pack("V")
    opt << [4, 0].pack("v v") << [0, 0].pack("v v") << [4, 0].pack("v v")
    opt << [0].pack("V") << [0x2000].pack("V") << [header_size].pack("V") << [0].pack("V")
    opt << [3].pack("v") << [0].pack("v")
    opt << [0x10_0000].pack("V") << [0x1000].pack("V")
    opt << [0x10_0000].pack("V") << [0x1000].pack("V")
    opt << [0].pack("V") << [16].pack("V")
    16.times { opt << [0, 0].pack("V V") }
    bytes << opt

    # one section header (.text)
    bytes << ".text\x00\x00\x00".b
    bytes << [1, text_rva, 0x200, header_size].pack("V V V V")
    bytes << [0, 0].pack("V V") << [0, 0].pack("v v")
    bytes << [0x60000020].pack("V")

    bytes << ("\x00".b * (header_size - bytes.bytesize))
    # .text content: just a RET
    text = "\xC3".b + ("\x00".b * (0x200 - 1))
    bytes << text
    bytes
  end

  # Build a minimal PE DLL with one named export pointing to fn_rva.
  def build_synth_dll_with_export(export_name, fn_rva)
    section_alignment = 0x1000
    file_alignment    = 0x200
    text_rva = 0x1000
    edata_rva = 0x2000
    header_size = 0x400

    # build .edata content: export directory + addr_funcs + addr_names +
    # addr_name_ords + name string
    funcs_rva = edata_rva + 40
    names_rva = funcs_rva + 4
    nameords_rva = names_rva + 4
    name_str_rva = nameords_rva + 2
    name_bytes = "#{export_name}\x00".b

    edata = +"".b
    edata << ([0, 0].pack("V V"))                  # Characteristics, TimeDateStamp
    edata << ([0, 0].pack("v v"))                  # MajorVersion, MinorVersion
    edata << ([0].pack("V"))                       # Name (DLL name RVA)
    edata << ([1].pack("V"))                       # Base ordinal
    edata << ([1, 1].pack("V V"))                  # NumberOfFunctions, NumberOfNames
    edata << ([funcs_rva, names_rva, nameords_rva].pack("V V V"))
    edata << ([fn_rva].pack("V"))                  # function RVAs
    edata << ([name_str_rva].pack("V"))            # name RVAs
    edata << ([0].pack("v"))                       # ordinal table
    edata << name_bytes

    # PE
    bytes = +"".b
    dos = ("\x00".b * 64); dos[0, 2] = "MZ"; dos[0x3C, 4] = [0x40].pack("V")
    bytes << dos
    bytes << "PE\x00\x00".b
    bytes << [0x014C, 2, 0, 0, 0, 0x00E0, 0x2102].pack("v v V V V v v") # DLL flag (0x2000)

    opt = +"".b
    opt << [0x10B].pack("v") << [1, 0].pack("C C")
    opt << [0x200].pack("V") << [0x200].pack("V") << [0].pack("V")
    opt << [0].pack("V") << [text_rva].pack("V") << [edata_rva].pack("V")
    opt << [0x60000000].pack("V") << [section_alignment].pack("V") << [file_alignment].pack("V")
    opt << [4, 0].pack("v v") << [0, 0].pack("v v") << [4, 0].pack("v v")
    opt << [0].pack("V") << [0x4000].pack("V") << [header_size].pack("V") << [0].pack("V")
    opt << [2].pack("v") << [0].pack("v") # SubsystemGUI
    opt << [0x10_0000].pack("V") << [0x1000].pack("V")
    opt << [0x10_0000].pack("V") << [0x1000].pack("V")
    opt << [0].pack("V") << [16].pack("V")
    dirs = Array.new(16) { [0, 0] }
    dirs[0] = [edata_rva, edata.bytesize] # EXPORT
    dirs.each { |va, sz| opt << [va, sz].pack("V V") }
    bytes << opt

    # 2 section headers
    bytes << ".text\x00\x00\x00".b
    bytes << [1, text_rva, 0x200, header_size].pack("V V V V")
    bytes << [0, 0].pack("V V") << [0, 0].pack("v v") << [0x60000020].pack("V")

    bytes << ".edata\x00\x00".b
    bytes << [edata.bytesize, edata_rva, 0x200, header_size + 0x200].pack("V V V V")
    bytes << [0, 0].pack("V V") << [0, 0].pack("v v") << [0x40000040].pack("V")

    bytes << ("\x00".b * (header_size - bytes.bytesize))
    text = "\xC3".b + ("\x00".b * (0x200 - 1))
    bytes << text
    bytes << edata + ("\x00".b * (0x200 - edata.bytesize))
    bytes
  end

  def build_minimal_image
    Exe32Rb::PE::Image.new(
      path: "/dev/null",
      machine: Exe32Rb::PE::Constants::MACHINE_I386,
      bitness: 32,
      characteristics: 0x102,
      subsystem: 3,
      image_base: 0x00400000,
      entry_point_rva: 0x1000,
      size_of_image: 0x10000,
      size_of_headers: 0x1000,
      section_alignment: 0x1000,
      file_alignment: 0x200,
      stack_reserve: 0x10000,
      stack_commit: 0x1000,
      heap_reserve: 0x10000,
      heap_commit: 0x1000,
      sections: [Exe32Rb::PE::Image::Section.new(
        name: ".text", virtual_size: 0x1000, virtual_address: 0x1000,
        size_of_raw_data: 0x1000, pointer_to_raw_data: 0x1000,
        characteristics: 0x60000020, raw_data: "\x00".b * 0x1000
      )],
      data_directories: Array.new(16) { Exe32Rb::PE::Image::DataDirectory.new(virtual_address: 0, size: 0) },
      imports: [],
      resources: {}
    )
  end

  def capture_stdout
    require "stringio"
    old = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = old
  end
end
