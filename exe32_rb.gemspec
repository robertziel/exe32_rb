require_relative "lib/exe32_rb/version"

Gem::Specification.new do |spec|
  spec.name        = "exe32_rb"
  spec.version     = Exe32Rb::VERSION
  spec.summary     = "Ruby emulator for 32-bit Windows PE32 / i386 executables."
  spec.description = <<~DESC
    Pure-Ruby PE32 / i386 emulator. Loads a 32-bit Windows .exe, maps
    its sections into a virtual address space, interprets x86
    instructions in 32-bit mode, and routes imported Windows API calls
    to Ruby handlers via the __stdcall / __cdecl conventions. Includes
    a host-backed kernel32 surface (real File I/O for CreateFileW /
    ReadFile / WriteFile / CloseHandle) and a signature table covering
    ~100 Win32 functions for permissive stub-missing emulation.
  DESC
  spec.authors     = ["exe32_rb authors"]
  spec.license     = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir["lib/**/*.rb", "exe/*", "tools/**/*.rb", "README.md"]
  spec.bindir      = "exe"
  spec.executables = ["exe32_rb"]
  spec.require_paths = ["lib"]
end
