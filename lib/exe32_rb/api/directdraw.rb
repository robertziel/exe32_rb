# frozen_string_literal: true

module Exe32Rb
  module Api
    # Minimum-viable DirectDraw → Ruby2D bridge.
    #
    # Routes the most basic DirectDraw call chain:
    #
    #     DirectDrawCreateEx(NULL, &ddraw, IID_IDirectDraw7, NULL)
    #     ddraw->SetCooperativeLevel(hwnd, DDSCL_NORMAL)
    #     ddraw->CreateSurface(&desc, &primary, NULL)
    #     primary->Blt(...)              ; copy bytes into our framebuffer
    #     primary->Flip(NULL, DDFLIP_WAIT) ; present
    #
    # to a Ruby2D::Window showing a single 640x480 framebuffer that we
    # blit each Flip. Full game speed isn't expected (we paint pixel-by-
    # pixel each frame) but it shows the binary's actual visual output.
    #
    # This is the minimum-viable end of the DirectDraw API; many real
    # games use blit-rectangles, color keys, hardware acceleration, etc.
    # Those will hit "method 7" / "method 8" stubs that return E_FAIL.
    module DirectDraw
      WIDTH  = 640
      HEIGHT = 480

      DD_OK = 0
      DDERR_GENERIC = 0x80004005

      IID_IDirectDraw7 = "15E65EC0-3B9C-11D2-B92F-00609787EA02".freeze
      IID_IDirectDrawSurface7 = "06675A80-3B9B-11D2-B92F-00609787EA02".freeze

      class << self
        attr_reader :framebuffer_addr, :primary_surface

        def install(machine)
          @machine = machine
          require "exe32_rb/api/com"
          Com.install(@machine) unless Com.objects

          @framebuffer_addr = @machine.scratch_alloc(WIDTH * HEIGHT * 4, zero: true)
          @primary_surface = nil

          register_ddraw_methods
          register_surface_methods
          install_ddraw_entrypoints
        end

        def register_ddraw_methods
          # IDirectDraw7 slots (after IUnknown 0..2):
          #  3 Compact
          #  4 CreateClipper
          #  5 CreatePalette
          #  6 CreateSurface(LPDDSURFACEDESC2 desc, LPDIRECTDRAWSURFACE7* surf, IUnknown* outer)
          # 19 GetDisplayMode
          # 20 SetCooperativeLevel(HWND hWnd, DWORD dwFlags)
          # 21 SetDisplayMode
          Com.register_method(IID_IDirectDraw7, 20, "SetCooperativeLevel", args: 2) { DD_OK }
          Com.register_method(IID_IDirectDraw7, 21, "SetDisplayMode", args: 5) { DD_OK }
          Com.register_method(IID_IDirectDraw7, 6,  "CreateSurface",  args: 3) do |_m, _args|
            # Return our pre-built primary surface object pointer through *args[1].
            obj = Com.get_or_create_object(IID_IDirectDrawSurface7)
            @primary_surface = obj
            @machine.memory.write_u32(_args[1] & 0xFFFF_FFFF, obj) if _args[1] != 0
            DD_OK
          end
        end

        def register_surface_methods
          # IDirectDrawSurface7 slots used most commonly:
          #  3  AddAttachedSurface
          #  5  Blt(LPRECT dst, LPDIRECTDRAWSURFACE7 src, LPRECT srcrect, DWORD flags, LPDDBLTFX fx)
          # 10  Flip(LPDIRECTDRAWSURFACE7 next, DWORD flags)
          # 11  GetAttachedSurface(caps, surf*)  → return same surface (back buffer same as primary in our model)
          # 25  Lock(rect, desc, flags, evt)   → write framebuffer addr into desc.lpSurface
          # 32  Unlock
          # 37  GetSurfaceDesc
          Com.register_method(IID_IDirectDrawSurface7, 5, "Blt", args: 5) { DD_OK }
          Com.register_method(IID_IDirectDrawSurface7, 10, "Flip", args: 2) do |_m, _args|
            present_frame
            DD_OK
          end
          Com.register_method(IID_IDirectDrawSurface7, 11, "GetAttachedSurface", args: 2) do |_m, args|
            # Return the same primary surface as the back buffer.
            @machine.memory.write_u32(args[1] & 0xFFFF_FFFF, @primary_surface) if args[1] != 0 && @primary_surface
            DD_OK
          end
          Com.register_method(IID_IDirectDrawSurface7, 25, "Lock", args: 4) do |m, args|
            desc_ptr = args[1] & 0xFFFF_FFFF
            if desc_ptr != 0
              # DDSURFACEDESC2 has lpSurface at offset 0x24 (Lock writes this so
              # the caller can fill the surface bytes directly).
              m.memory.write_u32(desc_ptr + 0x24, @framebuffer_addr)
              # lPitch at 0x10
              m.memory.write_u32(desc_ptr + 0x10, WIDTH * 4)
            end
            DD_OK
          end
          Com.register_method(IID_IDirectDrawSurface7, 32, "Unlock", args: 1) { DD_OK }
        end

        def install_ddraw_entrypoints
          dispatcher = @machine.dispatcher
          dispatcher.install_handler("ddraw.dll", "DirectDrawCreate", args: 3) do |m, args|
            obj = Com.get_or_create_object(IID_IDirectDraw7)
            m.memory.write_u32(args[1] & 0xFFFF_FFFF, obj) if args[1] != 0
            DD_OK
          end
          dispatcher.install_handler("ddraw.dll", "DirectDrawCreateEx", args: 4) do |m, args|
            obj = Com.get_or_create_object(IID_IDirectDraw7)
            m.memory.write_u32(args[1] & 0xFFFF_FFFF, obj) if args[1] != 0
            DD_OK
          end
        end

        # Called from Flip. If a Ruby2D window is registered, push the
        # current framebuffer into it. Otherwise just count frames.
        def present_frame
          @frame_count ||= 0
          @frame_count += 1
          @window&.refresh_framebuffer
        end

        attr_accessor :window
      end
    end
  end
end
