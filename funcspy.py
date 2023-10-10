# Author github.com/n0mi1k
# Malicious APIs from malapi.io

import pefile
import sys
import requests
from colorama import Fore, Style

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

MALAPIFUNCS = ['CreateToolhelp32Snapshot', 'EnumDeviceDrivers', 'EnumProcesses', 'EnumProcessModules', 'EnumProcessModulesEx', 'FindFirstFileA', 'FindNextFileA', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetModuleBaseNameA', 'GetSystemDefaultLangId', 'GetVersionExA', 'GetWindowsDirectoryA', 'IsWoW64Process', 'Module32First', 'Module32Next', 'Process32First', 'Process32Next', 'ReadProcessMemory', 'Thread32First', 'Thread32Next', 'GetSystemDirectoryA', 'GetSystemTime', 'ReadFile', 'GetComputerNameA', 'VirtualQueryEx', 'GetProcessIdOfThread', 'GetProcessId', 'GetCurrentThread', 'GetCurrentThreadId', 'GetThreadId', 'GetThreadInformation', 'GetCurrentProcess', 'GetCurrentProcessId', 'SearchPathA', 'GetFileTime', 'GetFileAttributesA', 'LookupPrivilegeValueA', 'LookupAccountNameA', 'GetCurrentHwProfileA', 'GetUserNameA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegQueryInfoKeyA', 'RegQueryMultipleValuesA', 'RegQueryValueExA', 'NtQueryDirectoryFile', 'NtQueryInformationProcess', 'NtQuerySystemEnvironmentValueEx', 'EnumDesktopWindows', 'EnumWindows', 'NetShareEnum', 'NetShareGetInfo', 'NetShareCheck', 'GetAdaptersInfo', 'PathFileExistsA', 'GetNativeSystemInfo', 'RtlGetVersion', 'GetIpNetTable', 'GetLogicalDrives', 'GetDriveTypeA', 'RegEnumKeyA', 'WNetEnumResourceA', 'WNetCloseEnum', 'FindFirstUrlCacheEntryA', 'FindNextUrlCacheEntryA', 'WNetAddConnection2A', 'WNetAddConnectionA', 'EnumResourceTypesA', 'EnumResourceTypesExA', 'GetSystemTimeAsFileTime', 'GetThreadLocale', 'EnumSystemLocalesA', 'CreateFileMappingA', 'CreateProcessA', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'GetModuleHandleA', 'GetProcAddress', 'GetThreadContext', 'HeapCreate', 'LoadLibraryA', 'LoadLibraryExA', 'LocalAlloc', 'MapViewOfFile', 'MapViewOfFile2', 'MapViewOfFile3', 'MapViewOfFileEx', 'OpenThread', 'Process32First', 'Process32Next', 'QueueUserAPC', 'ReadProcessMemory', 'ResumeThread', 'SetProcessDEPPolicy', 'SetThreadContext', 'SuspendThread', 'Thread32First', 'Thread32Next', 'Toolhelp32ReadProcessMemory', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'VirtualAllocExNuma', 'VirtualAlloc2', 'VirtualAlloc2FromApp', 'VirtualAllocFromApp', 'VirtualProtectFromApp', 'CreateThread', 'WaitForSingleObject', 'OpenProcess', 'OpenFileMappingA', 'GetProcessHeap', 'GetProcessHeaps', 'HeapAlloc', 'HeapReAlloc', 'GlobalAlloc', 'AdjustTokenPrivileges', 'CreateProcessAsUserA', 'OpenProcessToken', 'CreateProcessWithTokenW', 'NtAdjustPrivilegesToken', 'NtAllocateVirtualMemory', 'NtContinue', 'NtCreateProcess', 'NtCreateProcessEx', 'NtCreateSection', 'NtCreateThread', 'NtCreateThreadEx', 'NtCreateUserProcess', 'NtDuplicateObject', 'NtMapViewOfSection', 'NtOpenProcess', 'NtOpenThread', 'NtProtectVirtualMemory', 'NtQueueApcThread', 'NtQueueApcThreadEx', 'NtQueueApcThreadEx2', 'NtReadVirtualMemory', 'NtResumeThread', 'NtUnmapViewOfSection', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'NtWriteVirtualMemory', 'RtlCreateHeap', 'LdrLoadDll', 'RtlMoveMemory', 'RtlCopyMemory', 'SetPropA', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx', 'KeInsertQueueApc', 'Wow64SetThreadContext', 'NtSuspendProcess', 'NtResumeProcess', 'DuplicateToken', 'NtReadVirtualMemoryEx', 'CreateProcessInternal', 'EnumSystemLocalesA', 'UuidFromStringA', 'CreateFileMappingA', 'DeleteFileA', 'GetModuleHandleA', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryExA', 'LoadResource', 'SetEnvironmentVariableA', 'SetFileTime', 'Sleep', 'WaitForSingleObject', 'SetFileAttributesA', 'SleepEx', 'NtDelayExecution', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'CreateWindowExA', 'RegisterHotKey', 'timeSetEvent', 'IcmpSendEcho', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx', 'SetWaitableTimer', 'CreateTimerQueueTimer', 'CreateWaitableTimer', 'SetWaitableTimer', 'SetTimer', 'Select', 'ImpersonateLoggedOnUser', 'SetThreadToken', 'DuplicateToken', 'SizeOfResource', 'LockResource', 'CreateProcessInternal', 'TimeGetTime', 'EnumSystemLocalesA', 'UuidFromStringA', 'AttachThreadInput', 'CallNextHookEx', 'GetAsyncKeyState', 'GetClipboardData', 'GetDC', 'GetDCEx', 'GetForegroundWindow', 'GetKeyboardState', 'GetKeyState', 'GetMessageA', 'GetRawInputData', 'GetWindowDC', 'MapVirtualKeyA', 'MapVirtualKeyExA', 'PeekMessageA', 'PostMessageA', 'PostThreadMessageA', 'RegisterHotKey', 'RegisterRawInputDevices', 'SendMessageA', 'SendMessageCallbackA', 'SendMessageTimeoutA', 'SendNotifyMessageA', 'SetWindowsHookExA', 'SetWinEventHook', 'UnhookWindowsHookEx', 'BitBlt', 'StretchBlt', 'GetKeynameTextA', 'WinExec', 'FtpPutFileA', 'HttpOpenRequestA', 'HttpSendRequestA', 'HttpSendRequestExA', 'InternetCloseHandle', 'InternetOpenA', 'InternetOpenUrlA', 'InternetReadFile', 'InternetReadFileExA', 'InternetWriteFile', 'URLDownloadToFile', 'URLDownloadToCacheFile', 'URLOpenBlockingStream', 'URLOpenStream', 'Accept', 'Bind', 'Connect', 'Gethostbyname', 'Inet_addr', 'Recv', 'Send', 'WSAStartup', 'Gethostname', 'Socket', 'WSACleanup', 'Listen', 'ShellExecuteA', 'ShellExecuteExA', 'DnsQuery_A', 'DnsQueryEx', 'WNetOpenEnumA', 'FindFirstUrlCacheEntryA', 'FindNextUrlCacheEntryA', 'InternetConnectA', 'InternetSetOptionA', 'WSASocketA', 'Closesocket', 'WSAIoctl', 'ioctlsocket', 'HttpAddRequestHeaders', 'CreateToolhelp32Snapshot', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetTickCount', 'OutputDebugStringA', 'CheckRemoteDebuggerPresent', 'Sleep', 'GetSystemTime', 'GetComputerNameA', 'SleepEx', 'IsDebuggerPresent', 'GetUserNameA', 'NtQueryInformationProcess', 'ExitWindowsEx', 'FindWindowA', 'FindWindowExA', 'GetForegroundWindow', 'GetTickCount64', 'QueryPerformanceFrequency', 'QueryPerformanceCounter', 'GetNativeSystemInfo', 'RtlGetVersion', 'GetSystemTimeAsFileTime', 'CountClipboardFormats', 'CryptAcquireContextA', 'EncryptFileA', 'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey', 'CryptSetKeyParam', 'CryptGetHashParam', 'CryptSetKeyParam', 'CryptDestroyKey', 'CryptGenRandom', 'DecryptFileA', 'FlushEfsCache', 'GetLogicalDrives', 'GetDriveTypeA', 'CryptStringToBinary', 'CryptBinaryToString', 'CryptReleaseContext', 'CryptDestroyHash', 'EnumSystemLocalesA', 'ConnectNamedPipe', 'CopyFileA', 'CreateFileA', 'CreateMutexA', 'CreateMutexExA', 'DeviceIoControl', 'FindResourceA', 'FindResourceExA', 'GetModuleBaseNameA', 'GetModuleFileNameA', 'GetModuleFileNameExA', 'GetTempPathA', 'IsWoW64Process', 'MoveFileA', 'MoveFileExA', 'PeekNamedPipe', 'WriteFile', 'TerminateThread', 'CopyFile2', 'CopyFileExA', 'CreateFile2', 'GetTempFileNameA', 'TerminateProcess', 'SetCurrentDirectory', 'FindClose', 'SetThreadPriority', 'UnmapViewOfFile', 'ControlService', 'ControlServiceExA', 'CreateServiceA', 'DeleteService', 'OpenSCManagerA', 'OpenServiceA', 'RegOpenKeyA', 'RegOpenKeyExA', 'StartServiceA', 'StartServiceCtrlDispatcherA', 'RegCreateKeyExA', 'RegCreateKeyA', 'RegSetValueExA', 'RegSetKeyValueA', 'RegDeleteValueA', 'RegOpenKeyExA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegGetValueA', 'RegFlushKey', 'RegGetKeySecurity', 'RegLoadKeyA', 'RegLoadMUIStringA', 'RegOpenCurrentUser', 'RegOpenKeyTransactedA', 'RegOpenUserClassesRoot', 'RegOverridePredefKey', 'RegReplaceKeyA', 'RegRestoreKeyA', 'RegSaveKeyA', 'RegSaveKeyExA', 'RegSetKeySecurity', 'RegUnLoadKeyA', 'RegConnectRegistryA', 'RegCopyTreeA', 'RegCreateKeyTransactedA', 'RegDeleteKeyA', 'RegDeleteKeyExA', 'RegDeleteKeyTransactedA', 'RegDeleteKeyValueA', 'RegDeleteTreeA', 'RegDeleteValueA', 'RegCloseKey', 'NtClose', 'NtCreateFile', 'NtDeleteKey', 'NtDeleteValueKey', 'NtMakeTemporaryObject', 'NtSetContextThread', 'NtSetInformationProcess', 'NtSetInformationThread', 'NtSetSystemEnvironmentValueEx', 'NtSetValueKey', 'NtShutdownSystem', 'NtTerminateProcess', 'NtTerminateThread', 'RtlSetProcessIsCritical', 'DrawTextExA', 'GetDesktopWindow', 'SetClipboardData', 'SetWindowLongA', 'SetWindowLongPtrA', 'OpenClipboard', 'SetForegroundWindow', 'BringWindowToTop', 'SetFocus', 'ShowWindow', 'NetShareSetInfo', 'NetShareAdd', 'NtQueryTimer', 'GetIpNetTable', 'GetLogicalDrives', 'GetDriveTypeA', 'CreatePipe', 'RegEnumKeyA', 'WNetOpenEnumA', 'WNetEnumResourceA', 'WNetAddConnection2A', 'CallWindowProcA', 'NtResumeProcess', 'lstrcatA', 'ImpersonateLoggedOnUser', 'SetThreadToken', 'SizeOfResource', 'LockResource', 'UuidFromStringA']

def analyze_exe(exe_path):
    IMPORTS = {}
    DLLS = []
    try:
        pe = pefile.PE(exe_path)

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            DLLS.append(entry.dll.decode())
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dllName = entry.dll.decode()
            IMPORTS[dllName] = None
            tempFuncs = []

            for func in entry.imports:
                if func.name is not None:
                    tempFuncs.append(func.name.decode())
            IMPORTS[dllName] = tempFuncs
    except Exception as e:
        print(f"Error analyzing {exe_path}: {e}")

    return IMPORTS

def main():
    malwarePath = sys.argv[1]
    ImportTable = analyze_exe(malwarePath)
    print(GREEN + f"[+] Finding suspicious funcs for {malwarePath}..." + RESET)
    for key, value in ImportTable.items():
        print(RED + f"Associated DLL: {key}" + RESET)
        for func in value:
            if func in MALAPIFUNCS:
                print(YELLOW + f"\t{func}" + RESET)


if __name__ == "__main__":
    main()
