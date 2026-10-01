# Mac 家用伺服器

把一台 Mac 變成全家人的網路中心：用 **Tailscale** 連回家、**擋廣告**、**家用雲端硬碟**，
再加一個手機用的**控制台**，用按鈕就能管理每個人能用什麼、能用多久——不用寫程式、不用改路由器。

> 介面是繁體中文，為 iPhone 設計（也支援電腦、深色模式）。
> 給家人看的使用教學：<https://hitachi513.github.io/home-guide/>

## 功能

| | |
|---|---|
| 🔐 **連回家** | Tailscale VPN；可以讓家人用你家的網路上網（出口節點） |
| 🛡️ **擋廣告** | AdGuard Home，可以每個人設不同的上網限制（擋成人網站、封鎖 App） |
| ☁️ **家用雲端** | 外接硬碟變雲端：每人有自己的空間和容量上限、共用資料夾、30 天垃圾桶、分享連結（期限／密碼／次數）、照片和文件預覽、iPhone 照片自動備份 |
| 👨‍👩‍👧 **成員管理** | 每個人的權限、有效期限、可用時段、每天可用時數、流量報表；每人一個專屬網頁 |
| 📱 **控制台** | 4 位數密碼＋Face ID 上鎖、推播通知、Mac 狀態（CPU／記憶體／電池／趨勢圖）、網速測試、遠端遙控 |
| 🔒 **安全監測** | 安全分數、16 項健康檢查、可疑事件統計、自動封鎖、一鍵「自我攻擊測試」 |
| 🔑 **成員網頁密碼** | 秘密網址之外再加一道密碼；記住裝置 30 天、重設密碼會登出所有裝置、猜錯會鎖定 |
| 😀 **個人設定** | 成員點頭像可以換照片／表情符號、取暱稱、開大字、改密碼 |
| 🐞 **問題回報** | 家人在專屬網頁回報（可附截圖），GitHub issues 也一起列在控制台，可以改狀態、回覆、標籤 |
| 🚀 **Shadowrocket**（選用，預設關閉） | 讓不裝 Tailscale 的人用 Shadowrocket 連回家 ⚠️ 見下方「法律注意」 |

## 需要準備

- 一台一直開著、插著電的 Mac（macOS 13 以上，Apple 晶片或 Intel 都可以）
- 一顆外接硬碟（用來當雲端，選用）
- [Tailscale](https://tailscale.com/download/mac) 帳號（免費），在 Tailscale 後台打開 **MagicDNS** 和 **HTTPS 憑證**
- 選用：[Homebrew](https://brew.sh)（只有 Shadowrocket 功能需要）

## 安裝

```bash
git clone https://github.com/Hitachi513/mac-homeserver ~/homeserver
bash ~/homeserver/install.sh
```

安裝程式會問你幾個問題（控制台擁有者是哪個 Tailscale 帳號、哪顆是雲端硬碟、要不要開 Shadowrocket），
然後自動：

1. 下載 AdGuard Home 並完成初始設定（只聽本機，管理密碼隨機產生）
2. 安裝 Python 套件（`cryptography`、`cbor2`）
3. 設定開機自動啟動的背景服務
4. 用 `tailscale serve` 發布控制台（**只有你的 Tailscale 連得到**），用 Funnel 發布成員網頁

裝完之後照畫面上的「接下來」做：iPhone 打開控制台設定密碼、給 Python「完整取用磁碟」權限、
連結 Tailscale API（成員權限才能自動套用），最後建議執行防火牆加固：

```bash
sudo bash ~/homeserver/security/harden.sh
```

所有個人設定都在 `~/homeserver/config.json`（範例：[`config.example.json`](config.example.json)）。
想在控制台同時管理 GitHub 上的回報，在 config.json 加上 `"github_repo": "你的帳號/你的repo"`（需要先用 `gh auth login` 登入）。
移除：`bash ~/homeserver/uninstall.sh`（資料會保留）。

## 架構

```
iPhone ──Tailscale──▶ tailscale serve :443  ──▶ 控制台   127.0.0.1:8088（只信任 Tailscale 傳來的身分）
                      tailscale serve :3443 ──▶ AdGuard  127.0.0.1:3000
網路上任何人 ─Funnel─▶ :8443 /p/<秘密網址>   ──▶ 成員網頁 127.0.0.1:8090（不信任任何身分標頭）
                      :8443 /（選用）       ──▶ Xray     127.0.0.1:10080（Shadowrocket）
```

- 只用 Python 標準函式庫寫的伺服器（另外只需要 `cryptography` 和 `cbor2`），沒有資料庫，資料都是 JSON 檔（權限 600）
- 成員權限會即時轉成 Tailscale ACL（透過 Tailscale API），到期、時段、時數用完都會自動收回

## 安全

請先讀 [SECURITY.md](SECURITY.md)。重點：

- 控制台只接受**由 Tailscale 轉進來**的連線（會檢查連線來自哪個程式），本機其他程式無法冒用身分
- 對網路公開的只有成員網頁（128 位元隨機網址＋限速＋自動封鎖）和選用的 Shadowrocket 入口
- 控制台裡的「設定 → 安全」可以隨時看安全分數，並對自己跑一次攻擊測試

## ⚠️ 法律注意

Shadowrocket 功能本質上是代理伺服器。**在部分國家或地區，架設或使用這類服務可能違法。**
這個功能預設關閉，請先確認你所在地的法律，使用責任由你自行負擔。

## 授權

[MIT](LICENSE)。AdGuard Home（GPL-3.0）、Xray-core（MPL-2.0）、noVNC（MPL-2.0）、websockify（LGPL-3.0）
不包含在這個專案裡，由安裝程式從官方來源下載，各自依原本的授權使用。

---

<details><summary>English</summary>

**Mac Home Server** turns an always-on Mac into a family network hub: Tailscale VPN (with exit node),
AdGuard Home ad-blocking with per-person filters, an external-disk family cloud (quotas, shared folder, trash,
share links, previews, iPhone photo backup), per-member permissions/schedules/time quotas pushed to the Tailscale
ACL, and a mobile-first control panel (PIN + Face ID lock, Web Push, Mac health, security score and a built-in
self-attack test). An optional, off-by-default Shadowrocket (Xray) gateway is included — check your local laws first.

```bash
git clone https://github.com/Hitachi513/mac-homeserver ~/homeserver
bash ~/homeserver/install.sh
```

The UI is in Traditional Chinese. MIT licensed; third-party components are downloaded by the installer and keep
their own licenses. See [SECURITY.md](SECURITY.md) for the threat model.
</details>
