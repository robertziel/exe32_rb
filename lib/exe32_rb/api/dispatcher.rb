# frozen_string_literal: true

module Exe32Rb
  module Api
    # Routes guest CALLs into imported DLL functions to Ruby handlers.
    #
    # When the PE is loaded, each entry in the import table is assigned a
    # unique synthetic "thunk" address in a reserved virtual region. The IAT
    # in guest memory is patched so that `call [iat_slot]` lands at the thunk
    # address. The Machine's step loop notices RIP == thunk and dispatches
    # to the Ruby handler instead of decoding instructions.
    #
    # Each registered handler declares its argument count and (optionally)
    # its calling convention. The dispatcher uses the convention to:
    #   1. read N args off registers/stack at the moment of the call,
    #   2. invoke the handler with (machine, args_array) and capture the return,
    #   3. write the return value into the right return register, and
    #   4. pop the return address (and stack args for __stdcall) and resume.
    class Dispatcher
      THUNK_REGION_BASE_64 = 0x0000_7FFE_0000_0000
      THUNK_REGION_BASE_32 = 0x6000_0000
      THUNK_STRIDE         = 0x10
      DEFAULT_REGION_SZ    = 0x1000

      Entry = Struct.new(:handler, :args, :convention, keyword_init: true)

      def initialize(memory, mode: 64)
        @memory   = memory
        @mode     = mode
        @thunks   = {}
        @handlers = {}
        @missing  = nil
        @default_convention = mode == 64 ? Conventions::MsX64.new : Conventions::Stdcall32.new
        @region_base = mode == 64 ? THUNK_REGION_BASE_64 : THUNK_REGION_BASE_32
        @next     = @region_base
      end

      attr_reader :thunks

      def install_handler(dll, name, args: 0, convention: nil, &block)
        @handlers[key(dll, name)] = Entry.new(
          handler: block, args: args, convention: convention || @default_convention
        )
      end

      def install_missing_handler(args: 0, convention: nil, &block)
        @missing = Entry.new(
          handler: block, args: args, convention: convention || @default_convention
        )
      end

      def installed?(dll, name)
        @handlers.key?(key(dll, name))
      end

      # Install a Ruby handler at a synthetic thunk address. Returns the
      # address — caller chooses whether to write it into a function-pointer
      # slot, patch a JMP at a function entry, or both.
      def install_thunk(name, args: 0, convention: nil, &block)
        thunk_addr = @next
        @next += THUNK_STRIDE
        @thunks[thunk_addr] = Exe32Rb::PE::Image::Import.new(
          dll: "(stub)", name: name, iat_rva: nil
        )
        @handlers[key("(stub)", name)] = Entry.new(
          handler: block, args: args, convention: convention || @default_convention
        )
        thunk_addr
      end

      # Install a thunk, then patch `at_address` to point at it. Useful for
      # function-pointer interception (e.g. an in-binary memory manager).
      def install_call_stub(at_address, name: nil, args: 0, convention: nil, &block)
        name ||= format("stub_0x%x", at_address)
        thunk_addr = install_thunk(name, args: args, convention: convention, &block)
        if @mode == 64
          @memory.write_u64(at_address, thunk_addr)
        else
          @memory.write_u32(at_address, thunk_addr)
        end
        thunk_addr
      end

      def install_builtins
        Kernel32.install(self)
      end

      def bind_imports(image)
        required = [image.imports.size, 1].max * THUNK_STRIDE
        region_size = align_up(required, Emulator::Memory::PAGE_SIZE)
        region_size = [region_size, DEFAULT_REGION_SZ].max
        @memory.map(@region_base, region_size,
                    permissions: Emulator::Memory::PERM_RX, name: "api_thunks")

        thunk_size = @mode == 64 ? 8 : 4
        image.imports.each do |imp|
          addr = @next
          @next += THUNK_STRIDE
          @thunks[addr] = imp
          if thunk_size == 8
            @memory.write_u64(image.image_base + imp.iat_rva, addr)
          else
            @memory.write_u32(image.image_base + imp.iat_rva, addr & 0xFFFF_FFFF)
          end
        end
      end

      def thunk?(address)
        @thunks.key?(address)
      end

      # A handler may return :no_cleanup to signal it has already arranged
      # the guest's stack/EIP itself (used by SEH-style APIs that "jump"
      # to a guest handler instead of returning normally).
      SKIP_CLEANUP = :no_cleanup

      def invoke(address, machine)
        imp = @thunks.fetch(address)
        entry = @handlers[key(imp.dll, imp.name || "##{imp.ordinal}")] || @missing
        raise Exe32Rb::ExecutionError, "no handler for #{imp.display_name}" unless entry

        args   = entry.convention.read_args(machine, entry.args)
        result = entry.handler.call(machine, args)
        return if result == SKIP_CLEANUP

        entry.convention.return_value(machine, result || 0)
        entry.convention.cleanup(machine, entry.args)
      end

      private

      def key(dll, name)
        "#{dll.downcase}!#{name}"
      end

      def align_up(value, alignment)
        ((value + alignment - 1) / alignment) * alignment
      end
    end
  end
end
