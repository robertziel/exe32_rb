# frozen_string_literal: true

require "readline"

module Exe32Rb
  # Interactive step-debugger REPL for the i386 emulator.
  #
  # Loads an image, drops you at the entry point, and lets you step,
  # continue, set breakpoints, inspect registers/flags/memory/stack, and
  # disassemble forward. The goal is learning x86 by watching it execute,
  # not solving a real binary.
  #
  # Commands (also via `help`):
  #   s, step          execute one instruction
  #   n, next          step over a CALL (continue until rip lands on the
  #                    instruction immediately after); for non-CALL acts as step
  #   c, continue      run until breakpoint, halt, or fault
  #   b ADDR           set breakpoint at ADDR (hex with or without 0x)
  #   bd ADDR          delete breakpoint
  #   bl               list breakpoints
  #   r, regs          show all GPRs + eip + flags
  #   d, disasm [N]    disassemble N (default 8) instructions from current eip
  #   x ADDR [N]       dump N (default 64) bytes of memory at ADDR
  #   stack [N]        dump top N (default 8) dwords from esp
  #   imports          list IAT imports
  #   strings          dump RT_STRING resources
  #   h, help          this help
  #   q, quit          exit the debugger
  class Debugger
    PROMPT = "(exe32) "

    def initialize(machine)
      @machine = machine
      @breakpoints = {}
      @quit = false
    end

    def run
      banner
      while !@quit && !@machine.halted?
        line = read_command
        break if line.nil? # EOF (Ctrl-D)

        line = line.strip
        next if line.empty?

        dispatch(line)
      end
      puts "── halted, exit_code=#{@machine.exit_code || 0}" if @machine.halted?
    end

    private

    def banner
      puts "exe32_rb debugger — loaded #{File.basename(@machine.image.path)}"
      printf "  entry  0x%08X\n", @machine.image.entry_point
      printf "  rsp    0x%08X\n", @machine.cpu.rsp
      printf "  %d imports bound across %d DLLs\n",
             @machine.image.imports.size,
             @machine.image.imports.map(&:dll).uniq.size
      puts "  type `help` for commands"
      puts
    end

    def read_command
      Readline.readline(PROMPT, true)
    end

    def dispatch(line)
      cmd, *args = line.split
      case cmd
      when "s", "step"     then cmd_step
      when "n", "next"     then cmd_next
      when "c", "continue" then cmd_continue
      when "b"             then cmd_break(args)
      when "bd"            then cmd_break_delete(args)
      when "bl"            then cmd_break_list
      when "r", "regs"     then cmd_regs
      when "d", "disasm"   then cmd_disasm(args)
      when "x"             then cmd_mem(args)
      when "stack"         then cmd_stack(args)
      when "imports"       then cmd_imports
      when "strings"       then cmd_strings
      when "h", "help", "?" then cmd_help
      when "q", "quit", "exit" then @quit = true
      else
        puts "unknown command: #{cmd}  (try `help`)"
      end
    rescue Exe32Rb::Error, ArgumentError => e
      puts "error: #{e.message}"
    end

    # ----------------------------------------------------------------
    # Execution control
    # ----------------------------------------------------------------

    def cmd_step
      perform_step
      show_current
    end

    def cmd_next
      rip = @machine.cpu.rip
      instr = @machine.decoder.decode(rip)
      after = (rip + instr.length) & @machine.cpu.address_mask
      if instr.mnemonic == :call || instr.mnemonic == :call_indirect
        # Step over: continue until we return to `after`
        run_until(after)
      else
        perform_step
      end
      show_current
    end

    def cmd_continue
      run_until_breakpoint
      show_current unless @machine.halted?
    end

    def perform_step
      @machine.step
    rescue Exe32Rb::MemoryError => e
      puts "fault: #{e.message}"
    end

    def run_until(target_rip)
      max = 10_000_000
      max.times do
        return if @machine.halted?
        return if @breakpoints.key?(@machine.cpu.rip) && @machine.cpu.rip != target_rip

        @machine.step
        return if @machine.cpu.rip == target_rip
      end
      puts "(step-over exceeded #{max} instructions; stopping)"
    rescue Exe32Rb::MemoryError => e
      puts "fault: #{e.message}"
    end

    def run_until_breakpoint
      max = 100_000_000
      max.times do
        return if @machine.halted?

        @machine.step
        if @breakpoints.key?(@machine.cpu.rip)
          puts "── breakpoint hit at 0x#{@machine.cpu.rip.to_s(16).upcase}"
          return
        end
      end
      puts "(continue exceeded #{max} instructions; stopping)"
    rescue Exe32Rb::MemoryError => e
      puts "fault: #{e.message}"
    end

    # ----------------------------------------------------------------
    # Breakpoints
    # ----------------------------------------------------------------

    def cmd_break(args)
      addr = parse_addr(args[0]) or return puts("usage: b ADDR")
      @breakpoints[addr] = true
      printf "breakpoint set at 0x%08X\n", addr
    end

    def cmd_break_delete(args)
      addr = parse_addr(args[0]) or return puts("usage: bd ADDR")
      if @breakpoints.delete(addr)
        printf "breakpoint cleared at 0x%08X\n", addr
      else
        puts "no breakpoint at 0x#{addr.to_s(16)}"
      end
    end

    def cmd_break_list
      if @breakpoints.empty?
        puts "(no breakpoints)"
      else
        @breakpoints.keys.sort.each { |a| printf "  0x%08X\n", a }
      end
    end

    # ----------------------------------------------------------------
    # State inspection
    # ----------------------------------------------------------------

    def cmd_regs
      r = @machine.cpu.registers
      printf "  eip = 0x%08X    flags = %s\n", @machine.cpu.rip, @machine.cpu.flags.to_s
      printf "  eax = 0x%08X    esi = 0x%08X\n", r.read32(0), r.read32(6)
      printf "  ebx = 0x%08X    edi = 0x%08X\n", r.read32(3), r.read32(7)
      printf "  ecx = 0x%08X    ebp = 0x%08X\n", r.read32(1), r.read32(5)
      printf "  edx = 0x%08X    esp = 0x%08X\n", r.read32(2), r.read32(4)
    end

    def cmd_disasm(args)
      count = args[0] ? Integer(args[0]) : 8
      rip = @machine.cpu.rip
      count.times do
        instr = @machine.decoder.decode(rip)
        marker = (rip == @machine.cpu.rip) ? "->" : "  "
        puts "#{marker} #{instr}"
        rip = (rip + instr.length) & @machine.cpu.address_mask
      end
    end

    def cmd_mem(args)
      addr = parse_addr(args[0]) or return puts("usage: x ADDR [N]")
      count = args[1] ? Integer(args[1]) : 64
      bytes = @machine.memory.read(addr, count).bytes
      bytes.each_slice(16).each_with_index do |row, i|
        hex   = row.map { |b| format("%02x", b) }.join(" ")
        ascii = row.map { |b| (32..126).cover?(b) ? b.chr : "." }.join
        printf "  0x%08X  %-47s  %s\n", addr + i * 16, hex, ascii
      end
    end

    def cmd_stack(args)
      count = args[0] ? Integer(args[0]) : 8
      esp = @machine.cpu.rsp
      count.times do |i|
        addr = (esp + i * 4) & @machine.cpu.address_mask
        value = @machine.memory.read_u32(addr)
        label = i == 0 ? " <- esp" : ""
        printf "  [esp+%2d]  0x%08X = 0x%08X%s\n", i * 4, addr, value, label
      end
    end

    def cmd_imports
      grouped = @machine.image.imports.group_by(&:dll)
      grouped.each do |dll, imps|
        puts "  #{dll}:"
        imps.each { |i| puts "    #{i.by_ordinal? ? "##{i.ordinal}" : i.name}" }
      end
    end

    def cmd_strings
      tree = @machine.image.resources[6]
      return puts("(no RT_STRING)") unless tree

      tree.keys.sort.each do |block_id|
        next unless block_id.is_a?(Integer)

        entry = @machine.image.find_resource(6, block_id)
        next unless entry

        base = @machine.image.image_base + entry[:data_rva]
        pos  = base
        16.times do |i|
          length = @machine.memory.read_u16(pos)
          pos += 2
          if length > 0
            text = @machine.memory.read(pos, length * 2).force_encoding("UTF-16LE").encode("UTF-8")
            uid = (block_id - 1) * 16 + i
            printf "  [%5d]  %s\n", uid, text
          end
          pos += length * 2
        end
      end
    end

    def cmd_help
      puts <<~HELP
        execution:
          s, step           execute one instruction
          n, next           step over a CALL (treats it as one logical line)
          c, continue       run until breakpoint or halt

        breakpoints:
          b   ADDR          set breakpoint at ADDR (hex: 0x401000 or 401000)
          bd  ADDR          delete breakpoint
          bl                list all breakpoints

        inspection:
          r, regs           registers + flags
          d, disasm [N]     disassemble N (default 8) instructions from eip
          x   ADDR [N]      dump N (default 64) bytes of memory
          stack [N]         show top N (default 8) dwords from esp
          imports           list IAT imports
          strings           dump RT_STRING resources

        misc:
          h, help           this help
          q, quit           exit
      HELP
    end

    def show_current
      return if @machine.halted?

      rip = @machine.cpu.rip
      instr = @machine.decoder.decode(rip)
      puts "-> #{instr}"
    rescue Exe32Rb::DecodeError, Exe32Rb::MemoryError => e
      puts "(cannot decode current eip: #{e.message})"
    end

    def parse_addr(s)
      return nil if s.nil?

      Integer(s.start_with?("0x") ? s : "0x#{s}")
    rescue ArgumentError
      nil
    end
  end
end
