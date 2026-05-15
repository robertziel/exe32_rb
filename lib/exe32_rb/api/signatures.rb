# frozen_string_literal: true

module Exe32Rb
  module Api
    # Known Win32 / Win64 function signatures (arg counts) plus a default
    # return value when stubbing. Used by `--stub-missing` to install
    # plausible no-op handlers without drifting the guest stack — every
    # __stdcall function needs the right callee-pops count or the next
    # POP/RET ends up reading garbage.
    #
    # When a real handler is installed elsewhere (e.g. in Kernel32.install),
    # that one wins; this table is the safety net.
    module Signatures
      # Each entry: name => [arg_count, default_return_value]
      KERNEL32 = {
        "GetACP"                       => [0, 1252],
        "GetCPInfo"                    => [2, 1],
        "GetTickCount"                 => [0, 0],
        "GetVersion"                   => [0, 0x0023_0A00],
        "GetVersionExA"                => [1, 1],
        "GetVersionExW"                => [1, 1],
        "GetCurrentProcess"            => [0, 0xFFFF_FFFF],
        "GetCurrentProcessId"          => [0, 1],
        "GetCurrentThreadId"           => [0, 1],
        "GetThreadLocale"              => [0, 0x0409],
        "GetUserDefaultLangID"         => [0, 0x0409],
        "GetLastError"                 => [0, 0],
        "SetLastError"                 => [1, 0],
        "GetStdHandle"                 => [1, 0],
        "GetCommandLineA"              => [0, 0],
        "GetCommandLineW"              => [0, 0],
        "GetStartupInfoA"              => [1, 0],
        "GetStartupInfoW"              => [1, 0],
        "GetModuleHandleA"             => [1, 0],
        "GetModuleHandleW"             => [1, 0],
        "GetModuleFileNameA"           => [3, 0],
        "GetModuleFileNameW"           => [3, 0],
        "GetWindowsDirectoryW"         => [2, 0],
        "GetSystemDirectoryW"          => [2, 0],
        "GetLocaleInfoW"               => [4, 0],
        "GetEnvironmentVariableW"      => [3, 0],
        "Sleep"                        => [1, 0],
        "GetSystemInfo"                => [1, 0],
        "GetNativeSystemInfo"          => [1, 0],
        "QueryPerformanceCounter"      => [1, 1],
        "QueryPerformanceFrequency"    => [1, 1],
        "GetSystemTimeAsFileTime"      => [1, 0],
        "VirtualAlloc"                 => [4, 0],
        "VirtualFree"                  => [3, 1],
        "VirtualProtect"               => [4, 1],
        "VirtualQuery"                 => [3, 0],
        "HeapCreate"                   => [3, 1],
        "HeapDestroy"                  => [1, 1],
        "HeapAlloc"                    => [3, 0],
        "HeapFree"                     => [3, 1],
        "HeapSize"                     => [3, 0],
        "GetProcessHeap"               => [0, 1],
        "LocalAlloc"                   => [2, 0],
        "LocalFree"                    => [1, 0],
        "GlobalAlloc"                  => [2, 0],
        "GlobalFree"                   => [1, 0],
        "TlsAlloc"                     => [0, 0],
        "TlsSetValue"                  => [2, 1],
        "TlsGetValue"                  => [1, 0],
        "TlsFree"                      => [1, 1],
        "InterlockedExchange"          => [2, 0],
        "InterlockedCompareExchange"   => [3, 0],
        "InterlockedIncrement"         => [1, 1],
        "InterlockedDecrement"         => [1, 0],
        "InitializeCriticalSection"    => [1, 0],
        "DeleteCriticalSection"        => [1, 0],
        "EnterCriticalSection"         => [1, 0],
        "LeaveCriticalSection"         => [1, 0],
        "InitializeCriticalSectionAndSpinCount" => [2, 1],
        "WaitForSingleObject"          => [2, 0],
        "SignalObjectAndWait"          => [4, 0],
        "SetEvent"                     => [1, 1],
        "ResetEvent"                   => [1, 1],
        "CreateEventW"                 => [4, 0],
        "CloseHandle"                  => [1, 1],
        "LoadLibraryA"                 => [1, 0x4000_0100],
        "LoadLibraryW"                 => [1, 0x4000_0100],
        "LoadLibraryExA"               => [3, 0x4000_0100],
        "LoadLibraryExW"               => [3, 0x4000_0100],
        "FreeLibrary"                  => [1, 1],
        "GetProcAddress"               => [2, 0],
        "FindResourceA"                => [3, 0],
        "FindResourceW"                => [3, 0],
        "FindResourceExW"              => [4, 0],
        "LoadResource"                 => [2, 0],
        "LockResource"                 => [1, 0],
        "SizeofResource"               => [2, 0],
        "CreateFileA"                  => [7, 0xFFFF_FFFF],
        "CreateFileW"                  => [7, 0xFFFF_FFFF],
        "ReadFile"                     => [5, 0],
        "WriteFile"                    => [5, 0],
        "SetFilePointer"               => [4, 0xFFFF_FFFF],
        "SetEndOfFile"                 => [1, 0],
        "GetFileSize"                  => [2, 0xFFFF_FFFF],
        "GetFileAttributesA"           => [1, 0xFFFF_FFFF],
        "GetFileAttributesW"           => [1, 0xFFFF_FFFF],
        "FindFirstFileA"               => [2, 0xFFFF_FFFF],
        "FindFirstFileW"               => [2, 0xFFFF_FFFF],
        "FindClose"                    => [1, 1],
        "DeleteFileW"                  => [1, 0],
        "CreateDirectoryW"             => [2, 0],
        "RemoveDirectoryW"             => [1, 0],
        "GetFullPathNameW"             => [4, 0],
        "GetDiskFreeSpaceW"            => [5, 0],
        "MultiByteToWideChar"          => [6, 0],
        "WideCharToMultiByte"          => [8, 0],
        "lstrlenA"                     => [1, 0],
        "lstrlenW"                     => [1, 0],
        "lstrcpyW"                     => [2, 0],
        "lstrcpynW"                    => [3, 0],
        "CreateProcessW"               => [10, 0],
        "GetExitCodeProcess"           => [2, 0],
        "TerminateProcess"             => [2, 1],
        "ExitProcess"                  => [1, 0],
        "SetErrorMode"                 => [1, 0],
        "RtlUnwind"                    => [4, 0],
        "RaiseException"               => [4, 0],
        "UnhandledExceptionFilter"     => [1, 1],
        "SetUnhandledExceptionFilter"  => [1, 0],
        "IsDebuggerPresent"            => [0, 0],
        "OutputDebugStringA"           => [1, 0],
        "OutputDebugStringW"           => [1, 0],
        "FormatMessageW"               => [7, 0],
        "EnumCalendarInfoW"            => [4, 1],
        "EnumCalendarInfoA"            => [4, 1],
        "IsProcessorFeaturePresent"    => [1, 0],
      }.freeze

      USER32 = {
        "GetKeyboardType"        => [1, 1],
        "LoadStringA"            => [4, 0],
        "LoadStringW"            => [4, 0],
        "MessageBoxA"            => [4, 1], # IDOK
        "MessageBoxW"            => [4, 1],
        "CharNextA"              => [1, 0],
        "CharNextW"              => [1, 0],
        "CharUpperBuffW"         => [2, 0],
        "CreateWindowExW"        => [12, 0],
        "DestroyWindow"          => [1, 1],
        "SetWindowLongW"         => [3, 0],
        "GetWindowLongW"         => [2, 0],
        "PeekMessageW"           => [5, 0],
        "TranslateMessage"       => [1, 0],
        "DispatchMessageW"       => [1, 0],
        "MsgWaitForMultipleObjects" => [5, 0],
        "GetSystemMetrics"       => [1, 0],
        "ExitWindowsEx"          => [2, 1],
        "CallWindowProcW"        => [5, 0],
      }.freeze

      ADVAPI32 = {
        "RegOpenKeyExA"          => [5, 2], # ERROR_FILE_NOT_FOUND
        "RegOpenKeyExW"          => [5, 2],
        "RegCloseKey"            => [1, 0],
        "RegQueryValueExA"       => [6, 2],
        "RegQueryValueExW"       => [6, 2],
        "OpenProcessToken"       => [3, 0],
        "LookupPrivilegeValueW"  => [3, 0],
        "AdjustTokenPrivileges"  => [6, 0],
      }.freeze

      OLEAUT32 = {
        "SysAllocStringLen"      => [2, 0],
        "SysReAllocStringLen"    => [3, 0],
        "SysFreeString"          => [1, 0],
      }.freeze

      COMCTL32 = {
        "InitCommonControls"     => [0, 0],
      }.freeze

      ALL = {
        "kernel32.dll" => KERNEL32,
        "user32.dll"   => USER32,
        "advapi32.dll" => ADVAPI32,
        "oleaut32.dll" => OLEAUT32,
        "comctl32.dll" => COMCTL32,
      }.freeze

      def self.lookup(dll, name)
        ALL[dll.downcase]&.[](name)
      end

      # Install no-op stubs (with correct arg count + sensible default
      # return) for every known signature that isn't already bound. Used as
      # a safety net so the guest stack doesn't drift after a stubbed call.
      def self.install_default_stubs(dispatcher)
        ALL.each do |dll, table|
          table.each do |name, (args, ret)|
            next if dispatcher.installed?(dll, name)

            dispatcher.install_handler(dll, name, args: args) { |_, _| ret }
          end
        end
      end
    end
  end
end
