# frozen_string_literal: true

require_relative "test_helper"
require "stringio"
require "tmpdir"

class HelloWorldTest < Minitest::Test
  def test_end_to_end_prints_hello
    Dir.mktmpdir do |dir|
      path = File.join(dir, "hello.exe")
      Exe32Rb::Samples::HelloWorld.write(path)

      machine = Exe32Rb::Machine.from_path(path).configure
      output = capture_stdout { machine.run }
      assert_equal "Hello, world!\n", output
    end
  end

  def test_hello_file_writes_a_real_file
    Dir.mktmpdir do |dir|
      exe = File.join(dir, "demo.exe")
      Exe32Rb::Samples::HelloFile.write(exe)

      Dir.chdir(dir) do
        machine = Exe32Rb::Machine.from_path(exe).configure
        machine.run
      end

      out = File.join(dir, Exe32Rb::Samples::HelloFile::OUTPUT_PATH)
      assert File.exist?(out), "expected #{out} to be written"
      assert_equal Exe32Rb::Samples::HelloFile::MESSAGE, File.read(out)
    end
  end

  def test_factorial_sample_returns_120
    Dir.mktmpdir do |dir|
      exe = File.join(dir, "fact.exe")
      Exe32Rb::Samples::Factorial.write(exe)

      machine = Exe32Rb::Machine.from_path(exe).configure
      machine.run
      assert_equal 120, machine.exit_code
    end
  end

  def test_machine_rejects_64bit_image
    Dir.mktmpdir do |dir|
      # Build a minimal x86_64 PE32+ header to confirm the gate.
      path = File.join(dir, "x64.exe")
      File.binwrite(path, x64_stub)

      err = assert_raises(ArgumentError) { Exe32Rb::Machine.from_path(path) }
      assert_match(/exe32_rb only supports/, err.message)
    end
  end

  private

  def capture_stdout
    old = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = old
  end

  # Smallest possible PE32+ that parses cleanly (entry not runnable; only
  # the architecture-check should trip).
  def x64_stub
    bytes = +"".b
    dos = ("\x00".b * 64)
    dos[0, 2] = "MZ"
    dos[0x3C, 4] = [0x40].pack("V")
    bytes << dos
    bytes << "PE\x00\x00".b
    bytes << [0x8664, 1, 0, 0, 0, 0xF0, 0x22].pack("v v V V V v v")
    opt = +"".b
    opt << [0x20B].pack("v")
    opt << [1, 0].pack("C C")
    14.times { opt << [0].pack("V") }
    opt << [0].pack("Q<")          # ImageBase
    16.times { opt << [0].pack("V") }
    opt << [0x100000].pack("Q<") << [0x1000].pack("Q<")
    opt << [0x100000].pack("Q<") << [0x1000].pack("Q<")
    opt << [0].pack("V")           # LoaderFlags
    opt << [16].pack("V")
    16.times { opt << [0, 0].pack("V V") }
    bytes << opt[0, 0xF0]
    # one section header so parser stays happy
    bytes << "fake\x00\x00\x00\x00".b
    bytes << [0, 0x1000, 0, 0, 0, 0].pack("V V V V V V")
    bytes << [0, 0].pack("v v") << [0].pack("V")
    bytes
  end
end
