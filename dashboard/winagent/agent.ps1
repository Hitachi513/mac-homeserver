# Home-server remote agent for Windows (Windows PowerShell 5.1, runs as the signed-in user, no window).
# It keeps one request open to the Mac's control panel through Tailscale and runs the commands that come back.
# Only the fixed commands in Invoke-Cmd exist; nothing received is ever run as code.
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$VER = '__VER__'
$Dir = Join-Path $env:LOCALAPPDATA 'HomeAgent'
$H = ([IO.File]::ReadAllText((Join-Path $Dir 'host'))).Trim()
$Token = ([IO.File]::ReadAllText((Join-Path $Dir 'token'))).Trim()
$PS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
$ArgLine = "--headless `"$PS`" -NoProfile -ExecutionPolicy Bypass -File `"$Dir\agent.ps1`""

$Mutex = New-Object Threading.Mutex($false, 'Local\HomeServerAgent')
if (-not $Mutex.WaitOne(0)) { exit }  # already running

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HANative {
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool LockWorkStation();
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO p);
    struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    public static void Key(byte vk) { keybd_event(vk, 0, 1, UIntPtr.Zero); keybd_event(vk, 0, 3, UIntPtr.Zero); }
    public static uint IdleSeconds() {
        var i = new LASTINPUTINFO(); i.cbSize = (uint)Marshal.SizeOf(i);
        return GetLastInputInfo(ref i) ? ((uint)Environment.TickCount - i.dwTime) / 1000 : 0;
    }
}
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    int f(); int g(); int h(); int i();
    int SetMasterVolumeLevelScalar(float level, Guid ctx);
    int j();
    int GetMasterVolumeLevelScalar(out float level);
    int k(); int l(); int m(); int n();
    int SetMute([MarshalAs(UnmanagedType.Bool)] bool mute, Guid ctx);
    int GetMute(out bool mute);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice { int Activate(ref Guid id, int ctx, int p, out IAudioEndpointVolume v); }
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator { int f(); int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice d); }
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumerator { }
public static class HAAudio {
    static IAudioEndpointVolume Vol() {
        var e = (IMMDeviceEnumerator)new MMDeviceEnumerator();
        IMMDevice d; Marshal.ThrowExceptionForHR(e.GetDefaultAudioEndpoint(0, 1, out d));
        var id = typeof(IAudioEndpointVolume).GUID; IAudioEndpointVolume v;
        Marshal.ThrowExceptionForHR(d.Activate(ref id, 23, 0, out v)); return v;
    }
    public static int Level { get { float f; Marshal.ThrowExceptionForHR(Vol().GetMasterVolumeLevelScalar(out f)); return (int)Math.Round(f * 100); }
                              set { Marshal.ThrowExceptionForHR(Vol().SetMasterVolumeLevelScalar(value / 100f, Guid.Empty)); } }
    public static bool Muted { get { bool m; Marshal.ThrowExceptionForHR(Vol().GetMute(out m)); return m; }
                               set { Marshal.ThrowExceptionForHR(Vol().SetMute(value, Guid.Empty)); } }
}
'@
[void][HANative]::SetProcessDPIAware()  # full-resolution screenshots on scaled displays

# ---- Windows media session (what's playing in Spotify, Chrome, Edge, ...) ----
$script:MediaOk = $false
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $script:AsTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    [void][Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager, Windows.Media.Control, ContentType = WindowsRuntime]
    $script:MediaOk = $true
} catch {}
function Wait-Op($op, [Type]$type) {
    $t = $script:AsTask.MakeGenericMethod($type).Invoke($null, @($op))
    if ($t.Wait(2000)) { return $t.Result }
}
function Get-Media {
    if (-not $script:MediaOk) { return $null }
    try {
        $mgr = Wait-Op ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager]::RequestAsync()) ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager])
        $s = $mgr.GetCurrentSession()
        if (-not $s) { return $null }
        $p = Wait-Op ($s.TryGetMediaPropertiesAsync()) ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties])
        $app = ($s.SourceAppUserModelId -split '[\\!]')[-1] -replace '\.exe$', ''
        return @{ track = $p.Title; artist = $p.Artist; app = $app
                  state = $(if ($s.GetPlaybackInfo().PlaybackStatus -eq 'Playing') { 'playing' } else { 'paused' }) }
    } catch { return $null }
}

function Get-Stats {
    $s = @{ user = $env:USERNAME; host = $env:COMPUTERNAME }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $s.os = "$($os.Caption) ($($os.BuildNumber))"
        $s.mem_total = [int64]$os.TotalVisibleMemorySize * 1024
        $s.mem_used = ([int64]$os.TotalVisibleMemorySize - [int64]$os.FreePhysicalMemory) * 1024
        $s.uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
    } catch {}
    try { $s.cpu_pct = [int](Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average } catch {}
    try {
        $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
        $s.disk_total = [int64]$d.Size; $s.disk_used = [int64]$d.Size - [int64]$d.FreeSpace
    } catch {}
    try {
        $p = [Windows.Forms.SystemInformation]::PowerStatus
        $s.on_ac = $p.PowerLineStatus -eq 'Online'
        if ($p.BatteryChargeStatus -notmatch 'NoSystemBattery' -and $p.BatteryLifePercent -le 1) { $s.battery = [int]($p.BatteryLifePercent * 100) }
    } catch {}
    try { $s.volume = [HAAudio]::Level; $s.muted = [HAAudio]::Muted } catch {}
    try { $s.idle_s = [int][HANative]::IdleSeconds() } catch {}
    $s.locked = [bool](Get-Process LogonUI -ErrorAction SilentlyContinue)
    $s.media = Get-Media
    return $s
}

function Show-Toast([string]$title, [string]$text) {
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    $e = [Security.SecurityElement]
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$($e::Escape($title))</text><text>$($e::Escape($text))</text></binding></visual></toast>")
    $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
}

$script:Synth = $null
function Invoke-Say([string]$text) {
    if (-not $script:Synth) {
        Add-Type -AssemblyName System.Speech
        $script:Synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
        $zh = $script:Synth.GetInstalledVoices() | Where-Object { $_.VoiceInfo.Culture.Name -like 'zh-*' } | Select-Object -First 1
        if ($zh) { $script:Synth.SelectVoice($zh.VoiceInfo.Name) }
    }
    $script:Synth.SpeakAsyncCancelAll()
    [void]$script:Synth.SpeakAsync($text)
}

function Get-Screenshot {
    $b = [Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object Drawing.Bitmap $b.Width, $b.Height
    $g = [Drawing.Graphics]::FromImage($bmp)
    try { $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size) } finally { $g.Dispose() }
    $scale = [Math]::Min(1.0, 1600.0 / $b.Width)
    $out = New-Object Drawing.Bitmap ([int]($b.Width * $scale)), ([int]($b.Height * $scale))
    $g = [Drawing.Graphics]::FromImage($out)
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.DrawImage($bmp, 0, 0, $out.Width, $out.Height); $g.Dispose(); $bmp.Dispose()
    $enc = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
    $ps = New-Object Drawing.Imaging.EncoderParameters 1
    $ps.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([Drawing.Imaging.Encoder]::Quality), ([long]70)
    $ms = New-Object IO.MemoryStream
    $out.Save($ms, $enc, $ps); $out.Dispose()
    return 'data:image/jpeg;base64,' + [Convert]::ToBase64String($ms.ToArray())
}

function Remove-Agent {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path ([Environment]::GetFolderPath('Startup')) 'HomeAgent.lnk')
    # the folder can't be deleted while this script runs from it; a short-lived helper does it after we exit
    Start-Process -WindowStyle Hidden -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c ping -n 4 127.0.0.1 >nul & rmdir /s /q `"$Dir`""
    $Mutex.ReleaseMutex()
    exit
}

function Invoke-Cmd($c) {
    $a = $c.arg
    $data = @{}
    switch ($c.name) {
        'media' {
            $vk = @{ playpause = 0xB3; next = 0xB0; prev = 0xB1 }[[string]$a.cmd]
            if (-not $vk) { throw '不支援的按鍵' }
            [HANative]::Key([byte]$vk)
        }
        'volume' { [HAAudio]::Muted = $false; [HAAudio]::Level = [Math]::Max(0, [Math]::Min(100, [int]$a.level)) }
        'mute' { [HAAudio]::Muted = -not [HAAudio]::Muted; $data.muted = [HAAudio]::Muted }
        'notify' { Show-Toast '📱 來自手機' ([string]$a.text) }
        'say' { Invoke-Say ([string]$a.text) }
        'open_url' {
            $u = [string]$a.url
            if ($u -notmatch '^https?://[^\s"]+$') { throw '只能開 http 或 https 網址' }
            Start-Process $u
        }
        'lock' { [void][HANative]::LockWorkStation() }
        'display_off' { [void][HANative]::SendMessage([IntPtr]0xFFFF, 0x0112, [IntPtr]0xF170, [IntPtr]2) }
        'sleep' {
            # sleep a moment later in a separate process, so the answer reaches the phone first
            $cmd = "Start-Sleep 3; Add-Type -AssemblyName System.Windows.Forms; [void][Windows.Forms.Application]::SetSuspendState('Suspend', `$false, `$false)"
            Start-Process -FilePath $Conhost -ArgumentList "--headless `"$PS`" -NoProfile -Command `"$cmd`"" -WindowStyle Hidden
        }
        'shutdown' { & shutdown.exe /s /t ([Math]::Max(10, [Math]::Min(3600, [int]$a.seconds))) /c '家裡的控制台要求關機' }
        'restart' { & shutdown.exe /r /t ([Math]::Max(10, [Math]::Min(3600, [int]$a.seconds))) /c '家裡的控制台要求重新開機' }
        'cancel_shutdown' { & shutdown.exe /a 2>$null; if ($LASTEXITCODE -ne 0) { throw '目前沒有排定的關機' } }
        'screenshot' {
            if (Get-Process LogonUI -ErrorAction SilentlyContinue) { throw '電腦已鎖定，看不到畫面' }
            $data.image = Get-Screenshot
        }
        'clipboard_get' { $t = Get-Clipboard -Raw; $data.text = $(if ($t) { $t.Substring(0, [Math]::Min($t.Length, 20000)) } else { '' }) }
        'clipboard_set' { Set-Clipboard -Value ([string]$a.text) }
        'uninstall' { $script:Uninstall = $true }
        default { throw '不支援的指令' }
    }
    return $data
}

function Send-Sync($payload) {
    $json = $payload | ConvertTo-Json -Depth 6 -Compress
    Invoke-RestMethod -Method Post -Uri "https://$H/agent/sync" -Headers @{ 'X-Agent-Token' = $Token } `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 90 -UseBasicParsing
}

$results = @()
$script:Uninstall = $false
while ($true) {
    try {
        $r = Send-Sync @{ ver = $VER; stats = (Get-Stats); results = $results }
        $results = @()
        if ($script:Uninstall -or $r.revoked) { Remove-Agent }
        if ($r.update) {
            # newer agent on the Mac: replace this file and hand over to the new copy
            $tmp = Join-Path $Dir 'agent.new'
            Invoke-WebRequest -UseBasicParsing -Headers @{ 'X-Agent-Token' = $Token } -Uri "https://$H/agent/agent.ps1" -OutFile $tmp
            Move-Item -Force $tmp (Join-Path $Dir 'agent.ps1')
            $Mutex.ReleaseMutex()
            Start-Process -FilePath $Conhost -ArgumentList $ArgLine -WindowStyle Hidden
            exit
        }
        foreach ($c in @($r.cmds)) {
            if (-not $c) { continue }
            try { $results += @{ id = $c.id; ok = $true; data = (Invoke-Cmd $c) } }
            catch { $results += @{ id = $c.id; ok = $false; error = $_.Exception.Message } }
        }
    } catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        if ($code -eq 410) { Remove-Agent }       # removed from the panel
        Start-Sleep -Seconds $(if ($code -eq 401) { 300 } else { 15 })
    }
}
