#!/bin/bash
# Run with: sudo bash ~/homeserver/security/harden.sh      (v2 — safe to run again)
set -u
# messages in the Mac user's language (we run as root, so ask as the user who called sudo)
UI_LANG="$(sudo -u "${SUDO_USER:-root}" defaults read -g AppleLanguages 2>/dev/null | sed -n 2p | tr -d ' ",')"
T() { local s="$1"; shift; /usr/bin/python3 "$(dirname "$(cd "$(dirname "$0")" && pwd)")/dashboard/i18n.py" "${UI_LANG:-${LANG:-zh-TW}}" "$s" "$@" 2>/dev/null || echo "$s"; }
[ "$(id -u)" = 0 ] || { echo "$(T '請用 sudo 執行')"; exit 1; }
_D="$(cd "$(dirname "$0")" && pwd)"
PREFIX="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("label_prefix","local.homeserver"))' "$(dirname "$_D")/config.json" 2>/dev/null || echo local.homeserver)"
PF_LABEL="$PREFIX.pf-homeserver"
DIR="$(cd "$(dirname "$0")" && pwd)"
OWNER="$(stat -f %Su "$DIR")"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
AGH="$(dirname "$DIR")/AdGuardHome/AdGuardHome"
ok(){ echo "  ✅ $*"; }
bad(){ echo "  ⚠️  $*"; }

echo "1) $(T 'macOS 防火牆：開啟、隱身模式、只自動允許 Apple 內建程式')"
$FW --setglobalstate on >/dev/null; $FW --setstealthmode on >/dev/null
$FW --setallowsigned on >/dev/null; $FW --setallowsignedapp off >/dev/null
$FW --add "$AGH" >/dev/null; $FW --unblockapp "$AGH" >/dev/null
ok "$($FW --getglobalstate)；$($FW --getstealthmode)"

echo "2) $(T '遠端服務只允許 Tailscale（Wi-Fi／網路上的人連不到 SSH、螢幕共享、檔案共享、DNS、AirPlay）')"
install -m 644 -o root -g wheel "$DIR/pf-homeserver.conf" /etc/pf.anchors/homeserver
STATUS="$DIR/pf-status.txt"
cat > /Library/LaunchDaemons/$PF_LABEL.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PF_LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
    <string>/sbin/pfctl -E 2>/dev/null; /sbin/pfctl -a com.apple/250.homeserver -f /etc/pf.anchors/homeserver 2>/dev/null; { date +%s; /sbin/pfctl -s info 2>/dev/null | head -1; /sbin/pfctl -a com.apple/250.homeserver -sr 2>/dev/null | grep -c . ; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate; /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode; /usr/bin/fdesetup status; } > "$STATUS"; chown $OWNER "$STATUS"; chmod 644 "$STATUS"</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>600</integer>
</dict></plist>
PLIST
chmod 644 /Library/LaunchDaemons/$PF_LABEL.plist
launchctl bootout system/$PF_LABEL 2>/dev/null
launchctl bootstrap system /Library/LaunchDaemons/$PF_LABEL.plist
sleep 2
if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' && pfctl -a com.apple/250.homeserver -sr 2>/dev/null | grep -q block; then
  ok "$(T '封包過濾已啟用，規則 {1} 條，開機自動套用、每 10 分鐘回報狀態' "$(pfctl -a com.apple/250.homeserver -sr 2>/dev/null | grep -c .)")"
else bad "$(T '封包過濾沒有啟用成功，請把這段畫面截圖給 Claude')"; fi

echo "3) $(T '檔案共享禁止訪客')"
defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false
ok "$(T 'SMB 訪客存取：關')"

echo "4) $(T '系統自動安全更新')"
U=/Library/Preferences/com.apple.SoftwareUpdate
for k in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall ConfigDataInstall AutomaticallyInstallMacOSUpdates; do defaults write $U $k -bool true; done
defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
ok "$(T '自動更新：開')"

echo "5) $(T '目前狀態')"
echo "  SSH: $(launchctl print system/com.openssh.sshd >/dev/null 2>&1 && T '開著（只有 Tailscale 連得到）' || T '關閉')"
echo "  FileVault：$(fdesetup status | head -1)"
echo; echo "$(T '完成！還原請執行：{1}' "sudo bash $DIR/undo.sh")"
