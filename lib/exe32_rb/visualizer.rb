# frozen_string_literal: true

require "ruby2d"

module Exe32Rb
  # Live visualizer: a Ruby2D window showing the emulator's state while
  # it executes. Useful for *watching* a binary run rather than reading
  # logs after the fact.
  #
  # Layout (1400x900):
  #
  #   +-- title bar (file name, steps, status) --------------------+
  #   | registers       | disassembly             | stack          |
  #   |                 |  -> 0x401000 push ebp   |  [esp+ 0] ...  |
  #   |  eax 00000005   |     0x401001 mov ebp,esp|  [esp+ 4] ...  |
  #   |  ...            |     0x401003 mov eax... |  ...           |
  #   |                 |                         |                |
  #   +-- log: recent API calls + SEH events ----------------------+
  #
  # Keyboard:
  #   space / s   step one instruction
  #   c           continue (run until paused/halt/fault)
  #   p           pause
  #   1..5        run 10, 100, 1k, 10k, 100k instructions
  #   q / esc     quit
  class Visualizer
    BG          = "#0c0c12"
    FG          = "#cccccc"
    HIGHLIGHT   = "#ffd700"
    DIM         = "#777788"
    GREEN       = "#7CFC00"
    RED         = "#FF6B6B"
    ORANGE      = "#FFA500"
    LIGHTBLUE   = "#87CEEB"

    FONT = "Menlo"
    FONT_SIZE = 14

    def initialize(machine, title: nil)
      @machine = machine
      @title   = title || File.basename(machine.image.path)
      @log     = []
      @log_max = 14
      @running = false
      @step_budget = 0
      @paused_msg = nil
    end

    def run
      install_log_hooks!
      build_window
      Ruby2D::Window.show
    end

    private

    def build_window
      ext = self
      Ruby2D::Window.set(title: "exe32_rb live — #{@title}",
                         width: 1400, height: 900, background: BG, fps_cap: 60)

      @title_text = Ruby2D::Text.new("", x: 16, y: 8, color: FG,
                                     size: FONT_SIZE + 4, font: FONT)
      @status_text = Ruby2D::Text.new("", x: 16, y: 32, color: DIM,
                                      size: FONT_SIZE - 2, font: FONT)

      @regs_label = Ruby2D::Text.new("Registers", x: 16, y: 60,
                                     color: ORANGE, size: FONT_SIZE, font: FONT)
      @regs_text  = Ruby2D::Text.new("", x: 16, y: 84, color: GREEN,
                                     size: FONT_SIZE, font: FONT)
      @flags_text = Ruby2D::Text.new("", x: 16, y: 84 + 14 * 11,
                                     color: LIGHTBLUE, size: FONT_SIZE, font: FONT)

      @disasm_label = Ruby2D::Text.new("Disassembly (-> = current eip)",
                                       x: 320, y: 60, color: ORANGE,
                                       size: FONT_SIZE, font: FONT)
      @disasm_text  = Ruby2D::Text.new("", x: 320, y: 84, color: FG,
                                       size: FONT_SIZE, font: FONT)
      @cur_marker   = Ruby2D::Rectangle.new(x: 316, y: 80,
                                            width: 760, height: FONT_SIZE + 4,
                                            color: "#2a2a3a")

      @stack_label = Ruby2D::Text.new("Stack", x: 1100, y: 60,
                                      color: ORANGE, size: FONT_SIZE, font: FONT)
      @stack_text  = Ruby2D::Text.new("", x: 1100, y: 84, color: FG,
                                      size: FONT_SIZE, font: FONT)

      @log_label = Ruby2D::Text.new("Event log (most recent at bottom)",
                                    x: 16, y: 620, color: ORANGE,
                                    size: FONT_SIZE, font: FONT)
      @log_text  = Ruby2D::Text.new("", x: 16, y: 644, color: DIM,
                                    size: FONT_SIZE - 2, font: FONT)

      @help_text = Ruby2D::Text.new(
        "[space/s] step  [c] continue  [p] pause  [1-5] burst (10,100,1k,10k,100k)  [q] quit",
        x: 16, y: 870, color: DIM, size: FONT_SIZE - 2, font: FONT)

      Ruby2D::Window.on(:key_down) do |event|
        ext.handle_key(event)
      end

      Ruby2D::Window.update do
        ext.tick
      end

      refresh
    end

    public

    def handle_key(event)
      case event.key
      when "space", "s" then perform_step
      when "c"          then @running = true
      when "p"          then @running = false
      when "1"          then @step_budget += 10
      when "2"          then @step_budget += 100
      when "3"          then @step_budget += 1_000
      when "4"          then @step_budget += 10_000
      when "5"          then @step_budget += 100_000
      when "q", "escape" then Ruby2D::Window.close
      end
    rescue Exe32Rb::Error => e
      log_event("ERROR: #{e.message}")
    end

    def tick
      return refresh if @machine.halted?

      if @running
        steps = 0
        until @machine.halted? || steps >= 5_000
          perform_step
          steps += 1
        end
      elsif @step_budget > 0
        burst = [@step_budget, 5_000].min
        burst.times do
          break if @machine.halted?

          perform_step
        end
        @step_budget -= burst
      end
      refresh
    end

    def perform_step
      @machine.step
    rescue Exe32Rb::MemoryError => e
      log_event("FAULT: #{e.message}")
      @running = false
    end

    def refresh
      update_title
      update_regs
      update_disasm
      update_stack
      update_log
    end

    def update_title
      @title_text.text = format("exe32_rb live — %s", @title)
      mode = if @machine.halted?
               "HALTED exit=#{@machine.exit_code}"
             elsif @running
               "RUNNING"
             elsif @step_budget > 0
               "BURST #{@step_budget} left"
             else
               "PAUSED"
             end
      @status_text.text = format(
        "steps=%d  mode=%d-bit  arch=%s  imports=%d  %s",
        @machine.steps_executed, @machine.mode,
        ExeRb_arch_name(@machine.image.machine),
        @machine.image.imports.size, mode
      )
    end

    def update_regs
      r = @machine.cpu.registers
      pairs = [
        ["eip", @machine.cpu.rip],
        ["eax", r.read32(0)], ["ebx", r.read32(3)],
        ["ecx", r.read32(1)], ["edx", r.read32(2)],
        ["esi", r.read32(6)], ["edi", r.read32(7)],
        ["ebp", r.read32(5)], ["esp", r.read32(4)],
      ]
      @regs_text.text = pairs.map { |n, v| format("%-3s 0x%08X", n, v) }.join("\n")
      @flags_text.text = "flags " + @machine.cpu.flags.to_s
    end

    def update_disasm
      rip = @machine.cpu.rip
      lines = []
      pos = rip
      30.times do
        instr = safe_decode(pos)
        break unless instr

        marker = pos == rip ? "->" : "  "
        lines << format("%s 0x%08X  %s", marker, pos,
                        instr_summary(instr))
        pos = (pos + instr.length) & @machine.cpu.address_mask
      end
      @disasm_text.text = lines.join("\n")
    end

    def update_stack
      esp = @machine.cpu.rsp
      lines = []
      18.times do |i|
        addr = (esp + i * 4) & @machine.cpu.address_mask
        v = safe_read_u32(addr)
        marker = i == 0 ? "<- esp" : ""
        lines << format("0x%08X  0x%08X %s", addr, v || 0, marker)
      end
      @stack_text.text = lines.join("\n")
    end

    def update_log
      lines = @log.last(@log_max)
      @log_text.text = lines.join("\n")
    end

    def safe_decode(addr)
      @machine.decoder.decode(addr)
    rescue Exe32Rb::Error, Exe32Rb::MemoryError
      nil
    end

    def safe_read_u32(addr)
      @machine.memory.read_u32(addr)
    rescue Exe32Rb::Error, Exe32Rb::MemoryError
      nil
    end

    def instr_summary(instr)
      raw = instr.raw.bytes.first(8).map { |b| format("%02x", b) }.join(" ")
      raw = raw.ljust(24)
      ops = instr.operands.map(&:to_s).join(", ")
      "#{raw}  #{instr.mnemonic}#{ops.empty? ? "" : " #{ops}"}"
    end

    def install_log_hooks!
      # Hook the dispatcher to log every API call (one line per import).
      vis = self
      original_invoke = @machine.dispatcher.method(:invoke)
      @machine.dispatcher.define_singleton_method(:invoke) do |address, mach|
        imp = thunks[address]
        vis.log_event("API  #{imp.display_name}") if imp
        original_invoke.call(address, mach)
      end
    end

    def log_event(msg)
      @log << msg
      @log.shift while @log.size > @log_max * 3
    end

    private

    def ExeRb_arch_name(machine_word)
      case machine_word
      when 0x014C then "i386"
      when 0x8664 then "x86_64"
      else format("0x%04X", machine_word)
      end
    end
  end
end
