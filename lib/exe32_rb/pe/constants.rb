# frozen_string_literal: true

module Exe32Rb
  module PE
    module Constants
      DOS_SIGNATURE = 0x5A4D       # "MZ"
      PE_SIGNATURE  = 0x00004550   # "PE\0\0"

      OPTIONAL_MAGIC_PE32  = 0x10B
      OPTIONAL_MAGIC_PE32P = 0x20B

      MACHINE_AMD64 = 0x8664
      MACHINE_I386  = 0x014C

      SUBSYSTEM_WINDOWS_CUI = 3
      SUBSYSTEM_WINDOWS_GUI = 2

      # Section characteristics (selected)
      SCN_CNT_CODE               = 0x00000020
      SCN_CNT_INITIALIZED_DATA   = 0x00000040
      SCN_CNT_UNINITIALIZED_DATA = 0x00000080
      SCN_MEM_DISCARDABLE        = 0x02000000
      SCN_MEM_EXECUTE            = 0x20000000
      SCN_MEM_READ               = 0x40000000
      SCN_MEM_WRITE              = 0x80000000

      # Data directory indices
      DIR_EXPORT         = 0
      DIR_IMPORT         = 1
      DIR_RESOURCE       = 2
      DIR_EXCEPTION      = 3
      DIR_SECURITY       = 4
      DIR_BASE_RELOC     = 5
      DIR_DEBUG          = 6
      DIR_ARCHITECTURE   = 7
      DIR_GLOBAL_PTR     = 8
      DIR_TLS            = 9
      DIR_LOAD_CONFIG    = 10
      DIR_BOUND_IMPORT   = 11
      DIR_IAT            = 12
      DIR_DELAY_IMPORT   = 13
      DIR_COM_DESCRIPTOR = 14

      IMPORT_ORDINAL_FLAG64 = 1 << 63

      def self.machine_name(value)
        case value
        when MACHINE_AMD64 then "AMD64 (x86_64)"
        when MACHINE_I386  then "I386"
        else format("0x%04X (unknown)", value)
        end
      end

      def self.subsystem_name(value)
        case value
        when SUBSYSTEM_WINDOWS_CUI then "Windows CUI"
        when SUBSYSTEM_WINDOWS_GUI then "Windows GUI"
        else format("%d", value)
        end
      end
    end
  end
end
