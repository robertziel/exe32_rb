# frozen_string_literal: true

require_relative "exe32_rb/version"

# Pure-Ruby emulator for 32-bit Windows PE32 / i386 executables. Parses the
# PE, maps it into virtual memory, interprets x86 instructions in 32-bit
# mode, and routes Win32 API calls to Ruby handlers via the __stdcall /
# __cdecl conventions.
module Exe32Rb
  class Error < StandardError; end
  class LoadError < Error; end
  class DecodeError < Error; end
  class ExecutionError < Error; end
  class MemoryError < Error; end

  ARCH = 32

  module PE
    autoload :Constants, "exe32_rb/pe/constants"
    autoload :Image,     "exe32_rb/pe/image"
    autoload :Loader,    "exe32_rb/pe/loader"
  end

  module Emulator
    autoload :Machine,     "exe32_rb/emulator/machine"
    autoload :Memory,      "exe32_rb/emulator/memory"
    autoload :Registers,   "exe32_rb/emulator/registers"
    autoload :Flags,       "exe32_rb/emulator/flags"
    autoload :CPU,         "exe32_rb/emulator/cpu"
    autoload :Decoder,     "exe32_rb/emulator/decoder"
    autoload :Instruction, "exe32_rb/emulator/instruction"
    autoload :Operand,     "exe32_rb/emulator/operand"
    autoload :Executor,    "exe32_rb/emulator/executor"
    autoload :FPU,         "exe32_rb/emulator/fpu"
    autoload :XMM,         "exe32_rb/emulator/xmm"
    autoload :JIT,         "exe32_rb/emulator/jit"
  end

  module Api
    autoload :Dispatcher,    "exe32_rb/api/dispatcher"
    autoload :Kernel32,      "exe32_rb/api/kernel32"
    autoload :Conventions,   "exe32_rb/api/conventions"
    autoload :Signatures,    "exe32_rb/api/signatures"
    autoload :DelphiMemMgr,  "exe32_rb/api/delphi_memmgr"
    autoload :WinFS,         "exe32_rb/api/win_fs"
    autoload :Com,           "exe32_rb/api/com"
    autoload :DllLoader,     "exe32_rb/api/dll_loader"
    autoload :DllLoaderInstall, "exe32_rb/api/dll_loader"
    autoload :DirectDraw,    "exe32_rb/api/directdraw"
    autoload :User32,        "exe32_rb/api/user32"
  end

  module Samples
    autoload :HelloWorld, "exe32_rb/samples/hello_world"
    autoload :HelloFile,  "exe32_rb/samples/hello_file"
    autoload :Factorial,  "exe32_rb/samples/factorial"
    autoload :HelloWindow, "exe32_rb/samples/hello_window"
  end

  autoload :CLI,        "exe32_rb/cli"
  autoload :Debugger,   "exe32_rb/debugger"
  autoload :Visualizer, "exe32_rb/visualizer"
  autoload :GUI,        "exe32_rb/gui"

  # Convenience: load a PE32 image and build a Machine ready to configure.run.
  # Rejects PE32+ / non-i386 images with a clear message.
  class Machine
    def self.from_path(path, **opts)
      image = Exe32Rb::PE::Loader.load(path)
      unless image.bitness == 32
        raise ArgumentError,
              "exe32_rb only supports PE32/i386; this image is " \
              "#{image.bitness}-bit #{Exe32Rb::PE::Constants.machine_name(image.machine)}"
      end

      Exe32Rb::Emulator::Machine.new(image, **opts)
    end
  end
end
