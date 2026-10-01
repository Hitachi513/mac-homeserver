#!/bin/bash
# 停止並移除背景服務和 Tailscale 發布設定。你的資料（成員、雲端檔案、設定）會保留。
set -u
BASE="$HOME/homeserver"
PREFIX="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("label_prefix","local.homeserver"))' "$BASE/config.json" 2>/dev/null || echo local.homeserver)"
TS="$(command -v tailscale || echo /Applications/Tailscale.app/Contents/MacOS/Tailscale)"
for n in homepanel adguardhome xray novnc; do
  launchctl bootout "gui/$(id -u)/$PREFIX.$n" 2>/dev/null && echo "  已停止 $PREFIX.$n"
  rm -f "$HOME/Library/LaunchAgents/$PREFIX.$n.plist"
done
"$TS" serve reset 2>/dev/null && echo "  已移除 Tailscale serve / funnel 設定"
echo
echo "完成。資料還在 $BASE；要連資料一起刪除請手動刪掉這個資料夾。"
echo "防火牆加固要還原的話：sudo bash $BASE/security/undo.sh"
