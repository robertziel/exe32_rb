#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Writes the bundled i386 hello-world .exe to examples/hello.exe.

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "exe32_rb"
require "fileutils"

dest = ARGV[0] || File.expand_path("../examples/hello.exe", __dir__)
FileUtils.mkdir_p(File.dirname(dest))
Exe32Rb::Samples::HelloWorld.write(dest)
puts "wrote #{dest} (#{File.size(dest)} bytes)"
