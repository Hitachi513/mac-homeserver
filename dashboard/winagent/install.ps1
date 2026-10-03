# Installs the home-server remote agent for the current Windows user (no administrator rights needed).
# Run from PowerShell:  irm https://<your Mac>.ts.net/agent/install.ps1?c=<pairing code> | iex
& {
    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $H = '__HOST__'
    $C = '__CODE__'
    $dir = Join-Path $env:LOCALAPPDATA 'HomeAgent'
    $startup = Join-Path ([Environment]::GetFolderPath('Startup')) 'HomeAgent.lnk'

    function Say($t, $c = 'Gray') { Write-Host $t -ForegroundColor $c }

    try {
        Say '正在連接家裡的 Mac…'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        # stop an older copy first (re-pairing the same PC)
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*HomeAgent\agent.ps1*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

        $body = [Text.Encoding]::UTF8.GetBytes((@{ code = $C; name = $env:COMPUTERNAME } | ConvertTo-Json -Compress))
        $r = Invoke-RestMethod -Method Post -Uri "https://$H/agent/pair" -ContentType 'application/json; charset=utf-8' -Body $body -UseBasicParsing
        [IO.File]::WriteAllText((Join-Path $dir 'token'), $r.token)
        [IO.File]::WriteAllText((Join-Path $dir 'host'), $H)
        Invoke-WebRequest -UseBasicParsing -Headers @{ 'X-Agent-Token' = $r.token } -Uri "https://$H/agent/agent.ps1" -OutFile (Join-Path $dir 'agent.ps1')

        # start at every sign-in, with no window (conhost --headless keeps Windows Terminal from opening one)
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argline = "--headless `"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$dir\agent.ps1`""
        $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($startup)
        $lnk.TargetPath = Join-Path $env:SystemRoot 'System32\conhost.exe'
        $lnk.Arguments = $argline
        $lnk.WindowStyle = 7
        $lnk.Description = 'Home server remote agent'
        $lnk.Save()
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\conhost.exe') -ArgumentList $argline -WindowStyle Hidden

        Say ''
        Say '完成！現在可以用手機的控制台 → 遙控 來控制這台電腦了。' 'Green'
        Say '之後開機登入時會自動在背景執行，不會有視窗。'
        Say "要移除：在控制台按「移除這台電腦」，或刪除 $dir 和開機啟動裡的 HomeAgent。"
    } catch {
        $msg = $_.Exception.Message
        try { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch {}
        Say ''
        Say "安裝失敗：$msg" 'Red'
        Say '請確認這台電腦已經打開 Tailscale，並在控制台重新產生配對碼再試一次。' 'Yellow'
    }
}
