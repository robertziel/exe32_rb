# frozen_string_literal: true

module Exe32Rb
  module Api
    # gdi32.dll — minimal GDI primitives backed by Ruby2D overlays.
    #
    # Real Windows GDI is enormous. We implement just enough that a
    # Delphi VCL form (or any simple Win32 GUI) can paint its background
    # and place static text on the window. Buttons, edits, comboboxes
    # etc. are *separate windows* created via CreateWindowExW with class
    # name "BUTTON"/"EDIT"/etc, and rendering them needs a custom
    # widget toolkit — out of scope here.
    #
    # The functions we install:
    #
    #   GetDC, ReleaseDC                     → DC handle is just the HWND
    #   BeginPaint, EndPaint                 → return same DC + zero PAINTSTRUCT
    #   FillRect                             → push a Rectangle into the GUI
    #   TextOutA, TextOutW, DrawTextW        → push a Text into the GUI
    #   SetTextColor, SetBkColor, SetBkMode  → record per-DC state
    #   GetStockObject                       → return a sentinel handle
    #   CreateSolidBrush                     → handle that encodes RGB
    #   SelectObject, DeleteObject           → no-ops returning the prev/1
    #
    # Each paint operation goes through GUI#paint_op which pushes a
    # Ruby2D primitive command for the main thread to apply.
    module Gdi32
      class << self
        def install(machine, gui: Exe32Rb::GUI.instance)
          d = machine.dispatcher
          state = State.new

          install_dc(d, gui, state)
          install_paint(d, gui, state)
          install_text(d, gui, state, machine)
          install_objects(d, state)
        end

        private

        def install_dc(d, _gui, state)
          d.install_handler("user32.dll", "GetDC", args: 1) do |_m, args|
            state.dc_for(args[0] & 0xFFFF_FFFF)
          end
          d.install_handler("user32.dll", "ReleaseDC", args: 2) do |_m, _args|
            1
          end
        end

        def install_paint(d, _gui, state)
          # BeginPaint(hwnd, &PAINTSTRUCT) → HDC
          # PAINTSTRUCT layout:
          #   0  HDC       hdc
          #   4  BOOL      fErase
          #   8  RECT      rcPaint (4 LONGs)
          #  24  BOOL      fRestore
          #  28  BOOL      fIncUpdate
          #  32  BYTE      rgbReserved[32]
          d.install_handler("user32.dll", "BeginPaint", args: 2) do |machine, args|
            hwnd = args[0] & 0xFFFF_FFFF
            ps   = args[1] & 0xFFFF_FFFF
            dc   = state.dc_for(hwnd)
            window = Exe32Rb::GUI.instance.windows[hwnd]
            w = window ? window[:width]  : 800
            h = window ? window[:height] : 600
            if ps != 0
              machine.memory.write_u32(ps +  0, dc)
              machine.memory.write_u32(ps +  4, 1)        # fErase
              machine.memory.write_u32(ps +  8, 0)
              machine.memory.write_u32(ps + 12, 0)
              machine.memory.write_u32(ps + 16, w)
              machine.memory.write_u32(ps + 20, h)
              machine.memory.write_u32(ps + 24, 0)
              machine.memory.write_u32(ps + 28, 0)
            end
            dc
          end

          d.install_handler("user32.dll", "EndPaint", args: 2) { |_m, _args| 1 }

          # InvalidateRect(hwnd, lpRect, bErase) → repost WM_PAINT
          d.install_handler("user32.dll", "InvalidateRect", args: 3) do |_m, args|
            Exe32Rb::GUI.instance.post_message(args[0] & 0xFFFF_FFFF,
                                               Exe32Rb::GUI::WM_PAINT, 0, 0)
            1
          end

          # FillRect(hdc, lpRect, hBrush)
          d.install_handler("user32.dll", "FillRect", args: 3) do |machine, args|
            dc     = args[0] & 0xFFFF_FFFF
            rect_p = args[1] & 0xFFFF_FFFF
            brush  = args[2] & 0xFFFF_FFFF
            if rect_p != 0
              l = sign32(machine.memory.read_u32(rect_p +  0))
              t = sign32(machine.memory.read_u32(rect_p +  4))
              r = sign32(machine.memory.read_u32(rect_p +  8))
              b = sign32(machine.memory.read_u32(rect_p + 12))
              color = state.color_for_brush(brush)
              Exe32Rb::GUI.instance.paint_rect(state.hwnd_for_dc(dc),
                                               l, t, r - l, b - t, color)
            end
            1
          end
        end

        def install_text(d, _gui, state, _machine)
          d.install_handler("gdi32.dll", "SetTextColor", args: 2) do |_m, args|
            old = state.text_color
            state.text_color = args[1] & 0x00FF_FFFF
            old
          end
          d.install_handler("gdi32.dll", "SetBkColor", args: 2) do |_m, args|
            old = state.bk_color
            state.bk_color = args[1] & 0x00FF_FFFF
            old
          end
          d.install_handler("gdi32.dll", "SetBkMode", args: 2) do |_m, args|
            old = state.bk_mode
            state.bk_mode = args[1] & 0xFFFF_FFFF
            old
          end

          # TextOutW(hdc, x, y, lpString, cchString) → BOOL
          d.install_handler("gdi32.dll", "TextOutW", args: 5) do |machine, args|
            dc = args[0] & 0xFFFF_FFFF
            x  = sign32(args[1])
            y  = sign32(args[2])
            str_p = args[3] & 0xFFFF_FFFF
            cch   = args[4] & 0xFFFF_FFFF
            next 0 if str_p == 0 || cch == 0

            chars = (0...cch).map { |i| machine.memory.read_u16(str_p + i * 2) }.pack("v*")
            text  = chars.force_encoding("UTF-16LE").encode("UTF-8",
                                                            invalid: :replace,
                                                            undef:   :replace)
            Exe32Rb::GUI.instance.paint_text(state.hwnd_for_dc(dc),
                                             x, y, text,
                                             color: state.text_color || 0)
            1
          end
          d.install_handler("gdi32.dll", "TextOutA", args: 5) do |machine, args|
            dc = args[0] & 0xFFFF_FFFF
            x  = sign32(args[1])
            y  = sign32(args[2])
            str_p = args[3] & 0xFFFF_FFFF
            cch   = args[4] & 0xFFFF_FFFF
            next 0 if str_p == 0 || cch == 0

            chars = (0...cch).map { |i| machine.memory.read_u8(str_p + i) }
            text = chars.pack("C*").force_encoding("ASCII-8BIT").to_s
            Exe32Rb::GUI.instance.paint_text(state.hwnd_for_dc(dc),
                                             x, y, text,
                                             color: state.text_color || 0)
            1
          end

          # DrawTextW(hdc, lpchText, cchText, lpRect, uFormat) → height
          d.install_handler("user32.dll", "DrawTextW", args: 5) do |machine, args|
            dc      = args[0] & 0xFFFF_FFFF
            str_p   = args[1] & 0xFFFF_FFFF
            cch     = sign32(args[2])
            rect_p  = args[3] & 0xFFFF_FFFF
            next 0 if str_p == 0 || rect_p == 0
            cch = wstrlen(machine, str_p) if cch == -1
            chars = (0...cch).map { |i| machine.memory.read_u16(str_p + i * 2) }.pack("v*")
            text  = chars.force_encoding("UTF-16LE").encode("UTF-8",
                                                            invalid: :replace,
                                                            undef:   :replace)
            x = sign32(machine.memory.read_u32(rect_p +  0))
            y = sign32(machine.memory.read_u32(rect_p +  4))
            Exe32Rb::GUI.instance.paint_text(state.hwnd_for_dc(dc),
                                             x, y, text,
                                             color: state.text_color || 0)
            16 # pretend line height
          end
        end

        def install_objects(d, state)
          # GetStockObject(i) — 16 well-known indices. Return a sentinel
          # whose low bits encode the index so SelectObject / FillRect
          # can recognize stock brushes.
          d.install_handler("gdi32.dll", "GetStockObject", args: 1) do |_m, args|
            idx = args[0] & 0xFF
            0x9000_0000 | idx
          end

          # CreateSolidBrush(crColor) — encode RGB in the handle so
          # FillRect can recover it. RGB is in COLORREF format
          # (0x00BBGGRR).
          d.install_handler("gdi32.dll", "CreateSolidBrush", args: 1) do |_m, args|
            0x9100_0000 | (args[0] & 0x00FF_FFFF)
          end

          d.install_handler("gdi32.dll", "SelectObject", args: 2) { |_m, _args| 0 }
          d.install_handler("gdi32.dll", "DeleteObject", args: 1) { |_m, _args| 1 }
          d.install_handler("gdi32.dll", "DeleteDC",     args: 1) { |_m, _args| 1 }
          d.install_handler("gdi32.dll", "CreateCompatibleDC", args: 1) { |_m, args| args[0] }
          d.install_handler("gdi32.dll", "CreateCompatibleBitmap", args: 3) do |_m, _args|
            0x9200_0000
          end
          d.install_handler("gdi32.dll", "BitBlt", args: 9) { |_m, _args| 1 }
          d.install_handler("gdi32.dll", "MoveToEx", args: 4) { |_m, _args| 1 }
          d.install_handler("gdi32.dll", "LineTo",   args: 3) { |_m, _args| 1 }
          d.install_handler("gdi32.dll", "Rectangle", args: 5) { |_m, _args| 1 }
        end

        def sign32(v)
          v &= 0xFFFF_FFFF
          v < 0x8000_0000 ? v : v - 0x1_0000_0000
        end

        def wstrlen(machine, ptr)
          n = 0
          while machine.memory.read_u16(ptr + n * 2) != 0 && n < 4096
            n += 1
          end
          n
        end
      end

      # Per-emulator GDI state. One DC per HWND for simplicity.
      class State
        attr_accessor :text_color, :bk_color, :bk_mode

        def initialize
          @hwnd_to_dc = {}
          @dc_to_hwnd = {}
          @next_dc = 0xA000_0001
          @text_color = 0x000000
          @bk_color   = 0xFFFFFF
          @bk_mode    = 2 # OPAQUE
        end

        def dc_for(hwnd)
          @hwnd_to_dc[hwnd] ||= begin
            dc = @next_dc
            @next_dc += 1
            @dc_to_hwnd[dc] = hwnd
            dc
          end
        end

        def hwnd_for_dc(dc)
          @dc_to_hwnd[dc]
        end

        # Stock brush indices the system maps to fixed colors:
        STOCK_BRUSH_COLORS = {
          0 => 0xFFFFFF, # WHITE_BRUSH
          1 => 0xC0C0C0, # LTGRAY_BRUSH
          2 => 0x808080, # GRAY_BRUSH
          3 => 0x404040, # DKGRAY_BRUSH
          4 => 0x000000, # BLACK_BRUSH
        }.freeze

        def color_for_brush(handle)
          if (handle & 0xFF00_0000) == 0x9100_0000
            handle & 0x00FF_FFFF
          elsif (handle & 0xFF00_0000) == 0x9000_0000
            STOCK_BRUSH_COLORS[handle & 0xFF] || 0xFFFFFF
          else
            0xFFFFFF
          end
        end
      end
    end
  end
end
