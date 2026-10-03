#!/bin/bash
# 停止並移除背景服務和 Tailscale 發布設定。你的資料（成員、雲端檔案、設定）會保留。
set -u
BASE="$HOME/homeserver"
PREFIX="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("label_prefix","local.homeserver"))' "$BASE/config.json" 2>/dev/null || echo local.homeserver)"
UI_LANG="$(defaults read -g AppleLanguages 2>/dev/null | sed -n 2p | tr -d ' ",')"
T() { local s="$1"; shift; /usr/bin/python3 "$BASE/dashboard/i18n.py" "${UI_LANG:-${LANG:-zh-TW}}" "$s" "$@" 2>/dev/null || echo "$s"; }
TS="$(command -v tailscale || echo /Applications/Tailscale.app/Contents/MacOS/Tailscale)"
for n in homepanel adguardhome xray novnc; do
  launchctl bootout "gui/$(id -u)/$PREFIX.$n" 2>/dev/null && echo "  $(T '已停止 {1}' "$PREFIX.$n")"
  rm -f "$HOME/Library/LaunchAgents/$PREFIX.$n.plist"
done
"$TS" serve reset 2>/dev/null && echo "  $(T '已移除 Tailscale serve / funnel 設定')"
echo
echo "$(T '完成。資料還在 {1}；要連資料一起刪除請手動刪掉這個資料夾。' "$BASE")"
echo "$(T '防火牆加固要還原的話：{1}' "sudo bash $BASE/security/undo.sh")"
