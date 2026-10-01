# 安全說明

## 信任模型

| 入口 | 誰連得到 | 怎麼確認身分 |
|---|---|---|
| 控制台 `127.0.0.1:8088`（`tailscale serve :443`） | 只有你的 tailnet | Tailscale 傳入的 `Tailscale-User-Login`。伺服器會用 `netstat` 確認連線**真的來自 Tailscale 程式**，本機其他程式（例如透過代理連進來的人）即使偽造標頭也會被拒絕，並推播通知你。之後還要過 4 位數密碼／Face ID（WebAuthn）這一關 |
| 成員網頁 `127.0.0.1:8090`（Funnel `:8443/p`） | 網路上任何人 | 只認網址裡的 128 位元隨機權杖，**完全不看身分標頭** |
| 分享連結 `/p/s/<96 位元 id>/` | 拿到連結的人 | 可以加密碼（PBKDF2）、期限、下載次數 |
| Shadowrocket（Funnel `:8443/`，選用） | 有帳號的人 | 每人一組 VLESS UUID；Xray 擋掉所有內網、Tailscale 和本機位址 |

## 內建防護

- 成員網頁：每個位址 10 分鐘內猜錯 20 次就限速；一小時猜錯 40 次自動封鎖 24 小時（會推播通知）
- Tailscale Funnel 會用真實來源覆蓋 `X-Forwarded-For`，偽造來源 IP 繞不過限速（實測）
- 標頭 15 秒內沒送完就斷線（防 slowloris）、同時連線數有上限、JSON 請求最大 1 MB
- HSTS、CSP、`X-Frame-Options: DENY`、`nosniff`；伺服器不透露版本；公開端的錯誤訊息不含內部資訊
- 跨站請求（CSRF）檢查 `Origin` / `Sec-Fetch-Site`
- 雲端：每個路徑都在 realpath 之後重新確認沒有跑出自己的資料夾；HTML／SVG 等檔案一律當下載並加 `CSP: sandbox`
- 所有機密檔案權限 600；成員資料、金鑰、密碼不會被 git 追蹤（`.gitignore` 是允許清單）
- Tailscale ACL：只有擁有者能開 Funnel；成員只拿到你給的連接埠

## 建議再做

- `sudo bash security/harden.sh`：用 macOS 封包過濾讓 SSH、檔案共享、螢幕共享、AirPlay、DNS **只有 Tailscale 連得到**
- 打開 FileVault（注意：停電重開機後要先在 Mac 上輸入密碼，服務才會回來）
- 偶爾更新 AdGuard Home 和 Xray（不會自動更新）

## 回報漏洞

**請不要開公開的 issue，也不要在任何公開的地方討論細節**，修好之前壞人也看得到。

請用「私下回報」，只有維護者看得到：

1. 打開 <https://github.com/Hitachi513/mac-homeserver/security/advisories/new>（需要登入 GitHub）
2. **Title**：用一句話寫是什麼問題，例如「成員網頁可以不用密碼直接看到資料」
3. **Description**：寫怎麼發生的、影響什麼，最好附上重現步驟
4. 其他欄位可以不填，按最下面的 **Submit report**

維護者會收到通知，通常幾天內會在同一頁回覆你。修好後會發新版本，並在版本說明裡感謝你（如果你願意）。
