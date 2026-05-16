# frozen_string_literal: true

require "thread"

module Exe32Rb
  # Thread-safe bridge between the emulator and a Ruby2D window.
  #
  # macOS / SDL requires window operations on the main thread; the
  # emulator is happiest running uninterrupted on its own thread. So we
  # split:
  #
  #   * main thread          → owns the Ruby2D::Window, runs the event
  #                            loop, polls for incoming window-op commands
  #                            from the emulator, posts input events back.
  #   * emulator thread      → calls register_window/show_window/etc. from
  #                            user32 handlers, polls poll_message in
  #                            GetMessage/PeekMessage, hands paint pixels
  #                            via present_framebuffer.
  #
  # Communication is a pair of thread-safe Queues. The GUI is a singleton
  # because Ruby2D itself is global state.
  class GUI
    # A Win32 message the way GetMessage delivers it:
    #   hwnd, message, wparam, lparam, time, point_x, point_y
    Message = Struct.new(:hwnd, :message, :wparam, :lparam, :time, :pt_x, :pt_y)

    # Common Win32 message codes we synthesize.
    WM_NULL       = 0x0000
    WM_CREATE     = 0x0001
    WM_DESTROY    = 0x0002
    WM_PAINT      = 0x000F
    WM_CLOSE      = 0x0010
    WM_QUIT       = 0x0012
    WM_ERASEBKGND = 0x0014
    WM_KEYDOWN    = 0x0100
    WM_KEYUP      = 0x0101
    WM_CHAR       = 0x0102
    WM_MOUSEMOVE  = 0x0200
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP   = 0x0202
    WM_RBUTTONDOWN = 0x0204
    WM_RBUTTONUP   = 0x0205

    class << self
      def instance
        @instance ||= new
      end

      def reset!
        @instance = nil
      end
    end

    attr_reader :windows

    def initialize
      @windows = {}      # hwnd => { title:, width:, height:, wndproc:, class_name: }
      @messages = Queue.new
      @commands = Queue.new
      @framebuffer = nil  # latest [pixels_rgba, w, h, hwnd] pushed by guest
      @framebuffer_mutex = Mutex.new
      @active_hwnd = nil
      @want_quit = false
      @next_hwnd = 0x0001_0000
      @ruby2d_alive = false
      @ready_latch = Queue.new  # main thread pushes once Ruby2D is open
    end

    # The emulator thread blocks here until the main thread has called
    # run_event_loop and Ruby2D is showing a window (or has decided it
    # can't open one). After this returns, message_box / present_*
    # behave as if the GUI is live.
    def wait_until_ready
      @ready_latch.pop
      @ready_latch.push(:ready) # let any number of waiters through
    end

    # ---- Called from the EMULATOR thread ----

    # Register a window class (called from user32.RegisterClassExW). For
    # now we just track the WndProc address per class name; CreateWindowExW
    # resolves it when the actual HWND is born.
    def register_class(name, wndproc_addr)
      @classes ||= {}
      @classes[name] = wndproc_addr
    end

    def wndproc_for_class(name)
      @classes&.[](name)
    end

    # Allocate an HWND and stash window metadata. Returns the HWND.
    def register_window(class_name:, title:, x:, y:, width:, height:, wndproc:)
      hwnd = next_hwnd
      @windows[hwnd] = {
        class_name: class_name,
        title: title,
        x: x, y: y, width: width, height: height,
        wndproc: wndproc, visible: false,
      }
      @active_hwnd ||= hwnd
      hwnd
    end

    # Make the window appear on screen.
    def show_window(hwnd)
      w = @windows[hwnd] or return false
      w[:visible] = true
      enqueue_command(:show, hwnd)
      # Synthetic WM_PAINT so guest paints initial frame.
      post_message(hwnd, WM_PAINT, 0, 0)
      true
    end

    def destroy_window(hwnd)
      @windows.delete(hwnd)
      enqueue_command(:close, hwnd)
      true
    end

    # Called from emulator thread to pop the next message. Blocks unless
    # `wait` is false.
    def poll_message(wait: true)
      return @messages.pop if wait
      return nil if @messages.empty?

      @messages.pop(true)
    rescue ThreadError
      nil
    end

    # Post a synthetic message into the queue (used by user32 to deliver
    # WM_PAINT after ShowWindow, or by main-thread input events).
    def post_message(hwnd, msg, wparam, lparam)
      @messages.push(
        Message.new(hwnd, msg, wparam & 0xFFFF_FFFF, lparam & 0xFFFF_FFFF,
                    (Time.now.to_f * 1000).to_i & 0xFFFF_FFFF, 0, 0)
      )
    end

    # Hand the GUI a new framebuffer to present on next vsync. Pixel
    # layout is packed BGRA (DirectDraw's default) or whatever the caller
    # gives — we pass it through to Ruby2D unchanged.
    def present_framebuffer(hwnd, pixels:, width:, height:)
      @framebuffer_mutex.synchronize do
        @framebuffer = [hwnd, pixels, width, height]
      end
      enqueue_command(:present, hwnd)
    end

    # Display a modal message box. Blocks the emulator thread until the
    # main thread dismisses it (user clicks "OK" or the window closes).
    # Outside of a GUI session (no main-thread Ruby2D loop running),
    # returns immediately so headless / CLI usage isn't penalized.
    def message_box(caption:, text:)
      unless @ruby2d_alive
        # Headless path: print to stderr and return.
        return :no_gui
      end
      dismiss = Queue.new
      enqueue_command([:message_box, caption, text, dismiss], nil)
      dismiss.pop
    end

    def want_quit?
      @want_quit
    end

    def request_quit
      @want_quit = true
      @messages.push(Message.new(0, WM_QUIT, 0, 0, 0, 0, 0))
    end

    # ---- Called from the MAIN thread ----

    # Take the most recently-presented framebuffer (if any) and blit it
    # to the active Ruby2D image. Returns the [pixels, w, h] tuple or nil.
    def latest_framebuffer
      @framebuffer_mutex.synchronize { @framebuffer }
    end

    # Set up a single shared image that we update from successive
    # framebuffers. Called from gui_run.
    attr_accessor :surface_image

    # The main-thread Ruby2D event-loop entry point. Blocks until the
    # window is closed or the emulator requests quit.
    def run_event_loop(title: "exe32_rb", width: 800, height: 600)
      require "ruby2d"

      Ruby2D::Window.set(title: title, width: width, height: height,
                          background: "black")

      # Until DirectDraw integration lands we just keep a placeholder
      # text so users see the window is alive even when the guest hasn't
      # painted anything yet.
      placeholder = Ruby2D::Text.new(
        "exe32_rb window — waiting for guest paint",
        x: 16, y: 16, size: 14, color: "white"
      )

      Ruby2D::Window.update do
        pump_commands
        fb = latest_framebuffer
        if fb
          # Render the framebuffer as a series of pixels. Ruby2D doesn't
          # have a raw pixel-buffer API, so for now we just hide the
          # placeholder when a fb arrives and leave the window black —
          # the DirectDraw integration in a follow-on commit will use a
          # proper Image-backed surface.
          placeholder.remove if placeholder
          placeholder = nil
        end
        # If the emulator finished, close the OS window so the main
        # thread can return to the CLI.
        Ruby2D::Window.close if @want_quit
      end

      Ruby2D::Window.on(:key_down) do |evt|
        # Translate to a synthetic WM_KEYDOWN. Use the key's character
        # code as wParam (real Windows uses VK_*, but for diagnostics
        # this is enough).
        if @active_hwnd
          post_message(@active_hwnd, WM_KEYDOWN, evt.key.ord & 0xFF, 0)
        end
      end

      Ruby2D::Window.on(:mouse_down) do |evt|
        if @active_hwnd
          msg = evt.button == :left ? WM_LBUTTONDOWN : WM_RBUTTONDOWN
          lp = (evt.y & 0xFFFF) << 16 | (evt.x & 0xFFFF)
          post_message(@active_hwnd, msg, 0, lp)
        end
      end

      Ruby2D::Window.on(:mouse_up) do |evt|
        if @active_hwnd
          msg = evt.button == :left ? WM_LBUTTONUP : WM_RBUTTONUP
          lp = (evt.y & 0xFFFF) << 16 | (evt.x & 0xFFFF)
          post_message(@active_hwnd, msg, 0, lp)
        end
      end

      @ruby2d_alive = true
      # Tell any waiters that the GUI is set up. We push a sentinel into
      # the latch queue; the wait_until_ready helper re-pushes it so any
      # later check also succeeds.
      @ready_latch.push(:ready)
      Ruby2D::Window.show
      @ruby2d_alive = false
      request_quit
    end

    private

    def next_hwnd
      h = @next_hwnd
      @next_hwnd += 1
      h
    end

    def enqueue_command(cmd, hwnd)
      @commands.push([cmd, hwnd])
    end

    # ---- Command handlers run on the main thread ----

    def handle_show_command(hwnd)
      w = @windows[hwnd] or return
      Ruby2D::Window.set(title: w[:title]) if @ruby2d_alive
    end

    def handle_close_command(_hwnd)
      Ruby2D::Window.close if @ruby2d_alive
    end

    def handle_present_command(_hwnd)
      # Framebuffer is read by the update loop — nothing to do here yet.
      # When we wire the Image surface in a follow-on patch, this is
      # where we'll blit raw pixels.
    end

    # In pump_commands we dispatch by checking the first element of the
    # command tuple. Composite commands (like :message_box with payload)
    # are tagged with an array.
    def pump_commands
      until @commands.empty?
        cmd, hwnd = @commands.pop(true)
        if cmd.is_a?(Array)
          op = cmd[0]
          case op
          when :message_box
            handle_message_box_command(*cmd[1..])
          end
        else
          send(:"handle_#{cmd}_command", hwnd)
        end
      end
    rescue ThreadError
      # nothing to pop
    end

    def handle_message_box_command(caption, text, dismiss_queue)
      # Push a Text overlay; auto-dismiss after a short timeout so the
      # emulator can keep running. We're not blocking on actual user
      # input yet — a follow-on can add a button hit-test.
      overlay = Ruby2D::Text.new(
        "#{caption}\n#{text}\n\n(auto-dismiss in 3s)",
        x: 24, y: 24, size: 18, color: "white"
      )
      Thread.new do
        sleep 3
        overlay.remove rescue nil
        dismiss_queue.push(:ok)
      end
    end
  end
end
