#!/bin/bash
# Reverts harden.sh (firewall stays on; turn it off in System Settings if you really want)
[ "$(id -u)" = 0 ] || { echo "請用 sudo 執行"; exit 1; }
_D="$(cd "$(dirname "$0")" && pwd)"
PREFIX="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("label_prefix","local.homeserver"))' "$(dirname "$_D")/config.json" 2>/dev/null || echo local.homeserver)"
PF_LABEL="$PREFIX.pf-homeserver"
launchctl bootout system/$PF_LABEL 2>/dev/null
rm -f /Library/LaunchDaemons/$PF_LABEL.plist /etc/pf.anchors/homeserver
pfctl -a com.apple/250.homeserver -F rules 2>/dev/null
echo "已移除「只允許 Tailscale」的封包規則。SSH 請到 系統設定 → 共享 → 遠端登入 自行開啟。"
