function Invoke-SessionExec {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Command
    )
    if (-not [System.Management.Automation.PSTypeName]'NativeMethods'.Type) {
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.InteropServices;
        using Microsoft.Win32.SafeHandles;
        public class NativeMethods
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFO
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public int dwX;
                public int dwY;
                public int dwXSize;
                public int dwYSize;
                public int dwXCountChars;
                public int dwYCountChars;
                public int dwFillAttribute;
                public int dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }
            [DllImport("wtsapi32.dll", SetLastError = true)]
            public static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CreateProcessAsUser(
                IntPtr hToken,
                string lpApplicationName,
                string lpCommandLine,
                ref SECURITY_ATTRIBUTES lpProcessAttributes,
                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hObject);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
        }
"@
    }
    function ReadStream {
        param (
            [IntPtr]$handle
        )
        $result = ""
        $buffer = New-Object byte[] 4096
        $safeHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($handle, $false)
        $stream = [System.IO.FileStream]::new($safeHandle, [System.IO.FileAccess]::Read, 4096, $false)
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::Default)
        while (($line = $reader.ReadLine()) -ne $null) {
            $result += $line + "`n"
        }
        $reader.Close()
        $stream.Close()
        $safeHandle.Close()        
        return $result
    }
    function Execute-CommandInSession {
        param (
            [int]$SessionId,
            [string]$Command
        )
        $userToken = [IntPtr]::Zero
        if (-not [NativeMethods]::WTSQueryUserToken($SessionId, [ref]$userToken)) {
            throw [System.ComponentModel.Win32Exception]::New([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $sa = New-Object NativeMethods+SECURITY_ATTRIBUTES
        $sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)
        $sa.bInheritHandle = $true
        $si = New-Object NativeMethods+STARTUPINFO
        $pi = New-Object NativeMethods+PROCESS_INFORMATION
        $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $stdoutReadPipe = [IntPtr]::Zero
        $stdoutWritePipe = [IntPtr]::Zero
        $stderrReadPipe = [IntPtr]::Zero
        $stderrWritePipe = [IntPtr]::Zero
        if (-not [NativeMethods]::CreatePipe([ref]$stdoutReadPipe, [ref]$stdoutWritePipe, [ref]$sa, 0)) {
            throw [System.ComponentModel.Win32Exception]::New([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        if (-not [NativeMethods]::CreatePipe([ref]$stderrReadPipe, [ref]$stderrWritePipe, [ref]$sa, 0)) {
            throw [System.ComponentModel.Win32Exception]::New([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $si.dwFlags = 0x00000100 -bor 0x00000200 -bor 0x00000400 -bor 0x00000001 # STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
        $si.hStdOutput = $stdoutWritePipe
        $si.hStdError = $stderrWritePipe
        $si.wShowWindow = 0 # SW_HIDE
        $PowerShell = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $base64Command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
        $arguments = "-NoProfile -EncodedCommand $base64Command"
        if (-not [NativeMethods]::CreateProcessAsUser($userToken, $PowerShell, $arguments, [ref]$sa, [ref]$sa, $true, 0, [IntPtr]::Zero, $PWD.Path, [ref]$si, [ref]$pi)) {
            throw [System.ComponentModel.Win32Exception]::New([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        [void][NativeMethods]::CloseHandle($stdoutWritePipe)
        [void][NativeMethods]::CloseHandle($stderrWritePipe)
        $stdoutOutput = ReadStream -handle $stdoutReadPipe
        $stderrOutput = ReadStream -handle $stderrReadPipe
        # Clean up
        [void][NativeMethods]::CloseHandle($pi.hProcess)
        [void][NativeMethods]::CloseHandle($pi.hThread)
        [void][NativeMethods]::CloseHandle($userToken)
        [void][NativeMethods]::CloseHandle($stdoutReadPipe)
        [void][NativeMethods]::CloseHandle($stderrReadPipe)
        return $stdoutOutput + $stderrOutput
    }
    function Get-UserSessions {
        $quserOutput = quser
        $quserLines = $quserOutput | Select-Object -Skip 1
        $sessions = foreach ($line in $quserLines) {
            $cleanLine = $line -replace '>', ''
            $regex = '^\s*(\S*)\s+(\S*)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$'
            if ($cleanLine -match $regex) {
                [PSCustomObject]@{
                    Username    = $matches[1]
                    SessionName = $matches[2]
                    ID          = [int]$matches[3]
                    State       = $matches[4]
                    IdleTime    = $matches[5]
                    LogonTime   = $matches[6]
                }
            }
        }
        return $sessions
    }
    Write-Output ""
    $sessions = Get-UserSessions
    $CurrentSessionID = (Get-Process -PID $pid).SessionID
    $validStates = @("Active", "Connected", "ConnectQuery", "Shadow", "Disconnected", "Idle", "Disc", "Listen")
    if ($SessionID -eq "All") {
        foreach ($session in $sessions) {
            if ($session.ID -eq $CurrentSessionID -or -not $validStates -contains $session.State) { continue }            
            Write-Output ""
            Write-Output "[+] Invoke Command as $($session.Username) under Session ID:$($session.ID)"
            $output = Execute-CommandInSession -SessionId ($session.ID) -Command $Command
            Write-Output $output
            Write-Output ""
        }
    } else {
        $session = $sessions | Where-Object { $_.ID -eq $SessionID }
        if ($null -ne $session -and $validStates -contains $session.State) {
            Write-Output "[+] Invoke Command under Session ID:$SessionID"
            $output = Execute-CommandInSession -SessionId $SessionID -Command $Command
            Write-Output $output
        } 
    }
}
#Invoke-SessionExec -SessionID All -command whoami
