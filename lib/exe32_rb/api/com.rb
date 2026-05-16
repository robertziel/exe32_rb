# frozen_string_literal: true

module Exe32Rb
  module Api
    # Minimal COM (Component Object Model) framework — enough for binaries
    # that go `CoCreateInstance(some_class, ...)` and then make a handful
    # of method calls through the returned vtable.
    #
    # We synthesize a "fake object" for every CoCreateInstance call:
    #   - allocate 4 bytes for the interface pointer (the object itself)
    #   - allocate a vtable of N entries, each pointing to a Ruby thunk
    #   - IUnknown's three required slots (QueryInterface, AddRef, Release)
    #     come preinstalled with no-op handlers
    #
    # Subsequent CoCreateInstance calls for the same IID return the same
    # object pointer (so AddRef/Release patterns don't proliferate).
    #
    # The vtable thunks dispatch to Ruby via the standard dispatcher
    # under the "(com)" pseudo-DLL with a method name like "IID!Method".
    # Use Com.register_method(iid, vtable_index, name, args:, &block)
    # to provide an implementation; unregistered slots default to a
    # "return 0" stub (E_FAIL when interpreted as HRESULT, which is
    # typically what causes graceful caller fallback).
    module Com
      IUNKNOWN_SLOTS = 3   # QueryInterface, AddRef, Release

      class << self
        attr_reader :objects, :methods_by_iid

        def install(machine, default_vtable_size: 32)
          @machine = machine
          @objects = {}          # iid_string => guest_object_ptr
          @methods_by_iid = {}   # iid_string => { slot => [name, args, &handler] }
          @default_vtable_size = default_vtable_size

          # IUnknown defaults applied to every object
          @global_defaults = {
            0 => ["QueryInterface", 3, ->(_m, _a) { 0 }],          # S_OK, returns the same object
            1 => ["AddRef",         1, ->(_m, _a) { 1 }],          # refcount=1
            2 => ["Release",        1, ->(_m, _a) { 0 }],          # refcount=0
          }

          install_kernel_apis(machine.dispatcher)
        end

        # Register a custom vtable method for a given IID + slot index.
        # `args` is the number of stdcall args (NOT counting `this`).
        # The handler receives (machine, args_array) where args_array
        # already excludes `this` (which the dispatcher consumed first).
        def register_method(iid, slot, name, args:, &block)
          @methods_by_iid[iid.upcase] ||= {}
          @methods_by_iid[iid.upcase][slot] = [name, args, block]
        end

        # Build (or return cached) guest object pointer for the IID.
        def get_or_create_object(iid)
          iid_key = iid.upcase
          return @objects[iid_key] if @objects[iid_key]

          # Allocate the vtable (N pointers).
          vt_size = @default_vtable_size
          vtable_addr = @machine.scratch_alloc(vt_size * 4, zero: true)

          methods = @global_defaults.merge(@methods_by_iid[iid_key] || {})
          vt_size.times do |slot|
            name, args, handler = methods[slot] || ["unimpl_#{slot}", 0, ->(_m, _a) { 0 }]
            # COM methods are __stdcall with `this` as the first arg.
            # We register a handler that takes (args+1) stdcall args
            # (args + the `this` pointer) and dispatches.
            thunk = @machine.dispatcher.install_thunk(
              "com.#{iid_key[0, 8]}.slot#{slot}.#{name}",
              args: args + 1,
              convention: Conventions::Stdcall32.new,
            ) do |mach, a|
              # a[0] is `this`; drop it and forward the rest to the user handler.
              handler.call(mach, a[1..])
            end
            @machine.memory.write_u32(vtable_addr + slot * 4, thunk)
          end

          # Allocate the object: just a single dword that holds vtable ptr.
          obj_addr = @machine.scratch_alloc(8, zero: true)
          @machine.memory.write_u32(obj_addr, vtable_addr)
          @objects[iid_key] = obj_addr
        end

        private

        def install_kernel_apis(dispatcher)
          dispatcher.install_handler("ole32.dll", "CoInitialize",   args: 1) { 0 }
          dispatcher.install_handler("ole32.dll", "CoInitializeEx", args: 2) { 0 }
          dispatcher.install_handler("ole32.dll", "CoUninitialize", args: 0) { 0 }

          dispatcher.install_handler("ole32.dll", "CoTaskMemAlloc", args: 1) do |mach, a|
            mach.scratch_alloc(a[0] & 0xFFFF_FFFF, zero: true)
          end
          dispatcher.install_handler("ole32.dll", "CoTaskMemFree", args: 1) { 0 }

          # CoCreateInstance(REFCLSID, IUnknown*, dwContext, REFIID, void** ppv)
          # Read IID at args[3]; write our synthetic object's address to *args[4].
          dispatcher.install_handler("ole32.dll", "CoCreateInstance", args: 5) do |mach, a|
            iid_ptr = a[3] & 0xFFFF_FFFF
            out_ptr = a[4] & 0xFFFF_FFFF
            iid_bytes = mach.memory.read(iid_ptr, 16)
            iid = format_guid(iid_bytes)
            obj = get_or_create_object(iid)
            mach.memory.write_u32(out_ptr, obj) if out_ptr != 0
            0 # S_OK
          end
        end

        def format_guid(bytes)
          b = bytes.bytes
          format("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24),
                 b[4] | (b[5] << 8),
                 b[6] | (b[7] << 8),
                 b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        end
      end
    end
  end
end
