# frozen_string_literal: true

require "fileutils"

module Exe32Rb
  module Api
    # Translate guest "Windows" paths into a sandboxed host directory.
    #
    # Maps `C:\Foo\Bar.txt` -> `<root>/C/Foo/Bar.txt` on host disk. The
    # guest binary thinks it's running against a real Windows filesystem;
    # everything actually lands in a dedicated subdirectory we create on
    # demand (default: `<TMPDIR>/exe32_rb_root`).
    #
    # All path translation handles:
    #   - Drive letters (C:, D:, ...)
    #   - Forward and back slashes
    #   - UNC paths (\\?\C:\...) — stripped of the prefix
    #   - Relative paths (left untouched)
    #
    # This is set up once via WinFS.install(machine, root: PATH) and the
    # CreateFileW/CreateDirectoryW handlers consult it via Machine#fs_root.
    module WinFS
      def self.install(machine, root: default_root)
        FileUtils.mkdir_p(root)
        machine.fs_root = root
        warn format("[winfs] sandbox root: %s", root)
      end

      def self.default_root
        File.join(Dir.tmpdir, "exe32_rb_root")
      end

      # Translate a guest path to a host path. If it starts with a drive
      # letter or UNC prefix, route into the sandbox. Otherwise return as-is.
      def self.translate(root, guest_path)
        return guest_path if root.nil? || guest_path.nil? || guest_path.empty?

        # Strip common UNC prefixes
        path = guest_path
        path = path.sub(%r{\A\\\\\?\\}, "") # \\?\
        path = path.sub(%r{\A\\\\\.\\}, "") # \\.\

        if path =~ /\A([A-Za-z]):[\\\/]?(.*)\z/m
          drive = Regexp.last_match(1).upcase
          rest  = Regexp.last_match(2).tr("\\", "/")
          File.join(root, drive, rest)
        elsif path.start_with?("/")
          # Host-absolute path (Unix). Pass through unchanged so the binary
          # can read host files it has legitimate references to (e.g. its
          # own .exe image whose path it learned from GetModuleFileNameW).
          path
        else
          # Relative path: route into the synthetic C:\Temp under the sandbox
          # so the binary's "is-XXX.tmp" temp dir lands somewhere predictable
          # instead of polluting the cwd. Real Windows resolves these against
          # GetCurrentDirectory; we map them as if cwd = C:\Temp.
          File.join(root, "C", "Temp", path.tr("\\", "/"))
        end
      end
    end
  end
end
