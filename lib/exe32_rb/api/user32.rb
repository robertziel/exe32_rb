# frozen_string_literal: true

module Exe32Rb
  module Api
    # user32.dll — window creation + message pump backed by Exe32Rb::GUI.
    #
    # Installs real handlers for the small subset of user32 that an
    # InnoSetup wizard / Win32 hello-world needs to open a window and
    # process messages:
    #
    #   RegisterClassW / RegisterClassExW    → remember WndProc by class
    #   CreateWindowExW                      → allocate HWND, open window
    #   ShowWindow                           → make HWND visible + WM_PAINT
    #   DestroyWindow                        → close window
    #   GetMessageW / PeekMessageW           → pop from GUI message queue
    #   TranslateMessage                     → no-op (we synthesize VK_*)
    #   DispatchMessageW                     → invoke guest WndProc via
    #                                          Machine#call_guest (4 stdcall
    #                                          args: hwnd, msg, wp, lp)
    #   DefWindowProcW                       → no-op-ish (returns 0)
    #   PostQuitMessage                      → request_quit
    #   GetSystemMetrics                     → fixed screen-size stubs
    module User32
      class << self
        def install(machine, gui: Exe32Rb::GUI.instance)
          dispatcher = machine.dispatcher

          install_register_class(dispatcher, gui)
          install_create_window(dispatcher, gui, machine)
          install_show_destroy(dispatcher, gui)
          install_message_pump(dispatcher, gui, machine)
          install_misc(dispatcher, gui)
          install_message_box(dispatcher, gui, machine)
        end

        private

        # WNDCLASSW offsets we read out of the guest struct passed to
        # RegisterClassW. The struct layout (40 bytes):
        #   0  UINT     style
        #   4  WNDPROC  lpfnWndProc
        #   8  int      cbClsExtra
        #  12  int      cbWndExtra
        #  16  HINSTANCE hInstance
        #  20  HICON    hIcon
        #  24  HCURSOR  hCursor
        #  28  HBRUSH   hbrBackground
        #  32  LPCWSTR  lpszMenuName
        #  36  LPCWSTR  lpszClassName
        def install_register_class(dispatcher, gui)
          handler = lambda do |machine, args|
            wcptr = args[0] & 0xFFFF_FFFF
            next 0 if wcptr == 0
            wndproc = machine.memory.read_u32(wcptr + 4)
            name_ptr = machine.memory.read_u32(wcptr + 36)
            name = name_ptr == 0 ? "" : machine.read_wstring(name_ptr)
            gui.register_class(name, wndproc)
            # A real ATOM in [0xC000..0xFFFF]. We just hash the name.
            (0xC000 + (name.hash & 0x3FFF)) & 0xFFFF
          end
          dispatcher.install_handler("user32.dll", "RegisterClassW",   args: 1, &handler)

          # RegisterClassExW takes a WNDCLASSEXW (48 bytes) whose first
          # field is `cbSize`. The lpfnWndProc is at offset +8, name
          # pointer at +40.
          ex_handler = lambda do |machine, args|
            wcptr = args[0] & 0xFFFF_FFFF
            next 0 if wcptr == 0
            wndproc = machine.memory.read_u32(wcptr + 8)
            name_ptr = machine.memory.read_u32(wcptr + 40)
            name = name_ptr == 0 ? "" : machine.read_wstring(name_ptr)
            gui.register_class(name, wndproc)
            (0xC000 + (name.hash & 0x3FFF)) & 0xFFFF
          end
          dispatcher.install_handler("user32.dll", "RegisterClassExW", args: 1, &ex_handler)
        end

        # CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle,
        #                 x, y, nWidth, nHeight, hWndParent, hMenu,
        #                 hInstance, lpParam) → HWND
        def install_create_window(dispatcher, gui, _machine)
          dispatcher.install_handler("user32.dll", "CreateWindowExW", args: 12) do |machine, args|
            class_name_ptr = args[1] & 0xFFFF_FFFF
            title_ptr      = args[2] & 0xFFFF_FFFF
            _style         = args[3] & 0xFFFF_FFFF
            x              = sign32(args[4])
            y              = sign32(args[5])
            w              = sign32(args[6])
            h              = sign32(args[7])

            # Class name can be either a real LPCWSTR or an ATOM in the
            # low 16 bits (high bits zero). For the ATOM case we look up
            # by name-hash; for the pointer case we read the wide string.
            class_name =
              if (class_name_ptr & 0xFFFF_0000) == 0
                # ATOM — find a class name that hashes to it. Slow path
                # but rare; we just walk our table.
                gui.instance_variable_get(:@classes)&.keys&.find do |n|
                  (0xC000 + (n.hash & 0x3FFF)) == class_name_ptr
                end || ""
              else
                machine.read_wstring(class_name_ptr)
              end

            title   = title_ptr == 0 ? "" : machine.read_wstring(title_ptr)
            wndproc = gui.wndproc_for_class(class_name) || 0

            # Many Win32 programs pass CW_USEDEFAULT (0x80000000); pick
            # sensible defaults so the host window has a usable size.
            cw_use_default = -0x80000000
            x = 0   if x == cw_use_default
            y = 0   if y == cw_use_default
            w = 640 if w <= 0 || w == cw_use_default
            h = 480 if h <= 0 || h == cw_use_default

            hwnd = gui.register_window(
              class_name: class_name, title: title,
              x: x, y: y, width: w, height: h, wndproc: wndproc
            )

            # Synthesize WM_CREATE so guest's WndProc gets the standard
            # init message. Posted into the queue; will fire on the
            # next GetMessage.
            gui.post_message(hwnd, Exe32Rb::GUI::WM_CREATE, 0, 0)

            hwnd
          end
        end

        def install_show_destroy(dispatcher, gui)
          dispatcher.install_handler("user32.dll", "ShowWindow", args: 2) do |_machine, args|
            hwnd = args[0] & 0xFFFF_FFFF
            gui.show_window(hwnd) ? 1 : 0
          end
          dispatcher.install_handler("user32.dll", "UpdateWindow", args: 1) do |_machine, args|
            # Force a WM_PAINT to the window.
            gui.post_message(args[0] & 0xFFFF_FFFF,
                              Exe32Rb::GUI::WM_PAINT, 0, 0)
            1
          end
          dispatcher.install_handler("user32.dll", "DestroyWindow", args: 1) do |_machine, args|
            gui.destroy_window(args[0] & 0xFFFF_FFFF) ? 1 : 0
          end
        end

        # MSG struct (28 bytes):
        #   0  HWND  hwnd
        #   4  UINT  message
        #   8  WPARAM wParam
        #  12  LPARAM lParam
        #  16  DWORD time
        #  20  POINT pt (x, y)
        def install_message_pump(dispatcher, gui, machine)
          write_msg = ->(addr, m) {
            machine.memory.write_u32(addr +  0, m.hwnd & 0xFFFF_FFFF)
            machine.memory.write_u32(addr +  4, m.message & 0xFFFF_FFFF)
            machine.memory.write_u32(addr +  8, m.wparam & 0xFFFF_FFFF)
            machine.memory.write_u32(addr + 12, m.lparam & 0xFFFF_FFFF)
            machine.memory.write_u32(addr + 16, m.time & 0xFFFF_FFFF)
            machine.memory.write_u32(addr + 20, m.pt_x & 0xFFFF_FFFF)
            machine.memory.write_u32(addr + 24, m.pt_y & 0xFFFF_FFFF)
          }

          # GetMessageW blocks until a message is available. Returns 0 on
          # WM_QUIT, non-zero otherwise (-1 = error).
          dispatcher.install_handler("user32.dll", "GetMessageW", args: 4) do |mach, args|
            msg_ptr = args[0] & 0xFFFF_FFFF
            m = gui.poll_message(wait: true)
            write_msg.call(msg_ptr, m) if msg_ptr != 0
            m.message == Exe32Rb::GUI::WM_QUIT ? 0 : 1
          end

          # PeekMessageW does not block. wRemoveMsg & 1 (PM_REMOVE) decides
          # whether to actually consume the message.
          dispatcher.install_handler("user32.dll", "PeekMessageW", args: 5) do |mach, args|
            msg_ptr = args[0] & 0xFFFF_FFFF
            m = gui.poll_message(wait: false)
            if m
              write_msg.call(msg_ptr, m) if msg_ptr != 0
              1
            else
              0
            end
          end

          dispatcher.install_handler("user32.dll", "TranslateMessage", args: 1) do |_m, _args|
            0
          end

          # DispatchMessageW(LPMSG) — reads the MSG and calls the window's
          # WndProc with (hwnd, message, wParam, lParam). The return value
          # of the WndProc is the return value of DispatchMessage.
          dispatcher.install_handler("user32.dll", "DispatchMessageW", args: 1) do |mach, args|
            msg_ptr = args[0] & 0xFFFF_FFFF
            hwnd   = mach.memory.read_u32(msg_ptr +  0)
            msg    = mach.memory.read_u32(msg_ptr +  4)
            wparam = mach.memory.read_u32(msg_ptr +  8)
            lparam = mach.memory.read_u32(msg_ptr + 12)
            window = gui.windows[hwnd]
            wndproc = window && window[:wndproc]
            if wndproc && wndproc != 0
              mach.call_guest(wndproc, [hwnd, msg, wparam, lparam])
            else
              0
            end
          end
        end

        def install_misc(dispatcher, gui)
          dispatcher.install_handler("user32.dll", "DefWindowProcW", args: 4) do |_m, _args|
            0
          end
          dispatcher.install_handler("user32.dll", "PostQuitMessage", args: 1) do |_m, args|
            gui.request_quit
            0
          end
          # GetSystemMetrics indices we care about: SM_CXSCREEN=0, SM_CYSCREEN=1
          dispatcher.install_handler("user32.dll", "GetSystemMetrics", args: 1) do |_m, args|
            case args[0] & 0xFFFF_FFFF
            when 0 then 1920
            when 1 then 1080
            when 4 then 22 # SM_CYCAPTION
            else 0
            end
          end
          # CallWindowProcW(lpPrevWndFunc, hwnd, msg, wp, lp) — invoke
          # whichever WndProc the guest passes us with stdcall semantics.
          dispatcher.install_handler("user32.dll", "CallWindowProcW", args: 5) do |mach, args|
            proc_addr = args[0] & 0xFFFF_FFFF
            mach.call_guest(proc_addr, args[1..4].map { |a| a & 0xFFFF_FFFF })
          end
        end

        # MessageBoxW(hwndParent, lpText, lpCaption, uType) → IDOK (=1)
        #
        # If a GUI is running, ask it to display a real modal Ruby2D
        # message box and block until the user dismisses it. Otherwise
        # just print the message to stderr and return IDOK.
        def install_message_box(dispatcher, gui, _machine)
          dispatcher.install_handler("user32.dll", "MessageBoxW", args: 4) do |mach, args|
            text_ptr = args[1] & 0xFFFF_FFFF
            cap_ptr  = args[2] & 0xFFFF_FFFF
            text     = text_ptr == 0 ? "" : mach.read_wstring(text_ptr)
            caption  = cap_ptr == 0  ? "exe32_rb" : mach.read_wstring(cap_ptr)
            warn format("[MessageBoxW] %s: %s", caption.inspect, text.inspect)
            gui.message_box(caption: caption, text: text)
            1 # IDOK
          end

          # ANSI version: same behavior, ASCII strings.
          dispatcher.install_handler("user32.dll", "MessageBoxA", args: 4) do |mach, args|
            text = args[1] == 0 ? "" : mach.read_cstring(args[1] & 0xFFFF_FFFF)
            cap  = args[2] == 0 ? "exe32_rb" : mach.read_cstring(args[2] & 0xFFFF_FFFF)
            warn format("[MessageBoxA] %s: %s", cap.inspect, text.inspect)
            gui.message_box(caption: cap, text: text)
            1
          end
        end

        def sign32(v)
          v &= 0xFFFF_FFFF
          v < 0x8000_0000 ? v : v - 0x1_0000_0000
        end
      end
    end
  end
end
