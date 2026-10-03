# Mac 家用伺服器

**繁體中文** · [English](README.en.md)

把一台 Mac 變成全家人的網路中心：用 **Tailscale** 連回家、**擋廣告**、**家用雲端硬碟**，
再加一個手機用的**控制台**，用按鈕就能管理每個人能用什麼、能用多久——不用寫程式、不用改路由器。

> 介面支援 **繁體中文、English、简体中文、日本語、한국어、Español**，自動跟著手機語言，也可以按 🌐 自己選。
> 為 iPhone 設計（也支援電腦、深色模式）。
> 給家人看的使用教學：<https://hitachi513.github.io/home-guide/>

## 功能

| | |
|---|---|
| 🔐 **連回家** | Tailscale VPN；可以讓家人用你家的網路上網（出口節點） |
| 🛡️ **擋廣告** | AdGuard Home（預設 3 份名單，約 40 萬條），可以每個人設不同的上網限制（擋成人網站、封鎖 App）。DNS 擋不掉 YouTube 影片廣告，那個要用瀏覽器擴充功能 |
| ☁️ **家用雲端** | 外接硬碟變雲端：每人有自己的空間和容量上限、共用資料夾、30 天垃圾桶、分享連結（期限／密碼／次數）、照片和文件預覽、iPhone 照片自動備份 |
| 👨‍👩‍👧 **成員管理** | 每個人的權限、有效期限、可用時段、每天可用時數、流量報表；每人一個專屬網頁 |
| 🖥️ **遙控 Windows** | 一行指令裝好小程式，手機就能看 Windows 的狀態、控制音樂音量、通知、截圖、鎖定、關機（只透過 Tailscale，不用開防火牆） |
| 📱 **控制台** | 4 位數密碼＋Face ID 上鎖、推播通知、Mac 狀態（CPU／記憶體／電池／趨勢圖）、網速測試、遠端遙控 |
| 🔒 **安全監測** | 安全分數、16 項健康檢查、可疑事件統計、自動封鎖、一鍵「自我攻擊測試」 |
| 🔑 **成員網頁密碼** | 秘密網址之外再加一道密碼；記住裝置 30 天、重設密碼會登出所有裝置、猜錯會鎖定 |
| 😀 **個人設定** | 成員點頭像可以換照片／表情符號、取暱稱、開大字、改密碼 |
| 🐞 **問題回報** | 家人在專屬網頁回報（可附截圖），GitHub issues 也一起列在控制台，可以改狀態、回覆、標籤 |
| 🌐 **6 種語言** | 所有畫面、推播通知、安裝程式、Windows 遙控程式都會跟著使用者的語言 |
| 🚀 **Shadowrocket**（選用，預設關閉） | 讓不裝 Tailscale 的人用 Shadowrocket 連回家 ⚠️ 見下方「法律注意」 |

## 需要準備

- 一台一直開著、插著電的 Mac（macOS 13 以上，Apple 晶片或 Intel 都可以）
- 一顆外接硬碟（用來當雲端，選用）
- [Tailscale](https://tailscale.com/download/mac) 帳號（免費），在 Tailscale 後台打開 **MagicDNS** 和 **HTTPS 憑證**
  （裝完後還要把 Global nameserver 設成這台 Mac，擋廣告才會生效，安裝程式最後會告訴你怎麼做）
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
- 多語言：介面用繁體中文寫，`dashboard/i18n/strings.json` 對照每一句的其他語言翻譯；`python3 tools/i18n_extract.py --check` 會列出還沒翻譯的句子

## 安全

請先讀 [SECURITY.md](SECURITY.md)。重點：

- 控制台只接受**由 Tailscale 轉進來**的連線（會檢查連線來自哪個程式），本機其他程式無法冒用身分
- 對網路公開的只有成員網頁（128 位元隨機網址＋限速＋自動封鎖）和選用的 Shadowrocket 入口
- 控制台裡的「設定 → 安全」可以隨時看安全分數，並對自己跑一次攻擊測試

## 回報問題／建議

| 你是… | 到哪裡回報 |
|---|---|
| 🐞 遇到 bug、安裝失敗、跟說明不一樣 | [開一個「回報問題」](https://github.com/Hitachi513/mac-homeserver/issues/new?template=bug_report.yml) |
| 💡 想要新功能、覺得哪裡可以更好用 | [開一個「建議新功能」](https://github.com/Hitachi513/mac-homeserver/issues/new?template=feature_request.yml) |
| 🔒 發現安全漏洞 | **不要公開**，請[私下回報](https://github.com/Hitachi513/mac-homeserver/security/advisories/new) |
| 🙋 不熟 GitHub | 在你自己的**控制台 → 成員 → 回報 → 回報給系統作者**，填中文表單，系統會自動整理好並遮掉個人資料，按一下就打開填好的 GitHub 頁面 |
| 👨‍👩‍👧 你是某個家庭的成員（別人幫你架的） | 在你的**專屬網頁**按「回報問題」，會直接送給幫你架設的人 |

需要 GitHub 帳號（免費）。表單是中英雙語的，照著填就好。詳細說明請看 [CONTRIBUTING.md](CONTRIBUTING.md)。

**回報前請先：**
1. 到 [Issues](https://github.com/Hitachi513/mac-homeserver/issues?q=is%3Aissue) 搜尋看看，是不是有人回報過了（有的話在下面留言 +1 並補充你的情況）
2. 更新到最新版再試一次：`cd ~/homeserver && git pull`，然後重新啟動控制台
3. **把個人資料遮掉**：Tailscale 網址（`xxx.ts.net`）、IP、成員名字、密碼、專屬網址都不要貼上來

**附上這些，會修得比較快：**
```bash
# 版本
cd ~/homeserver && git describe --tags
# macOS 版本和晶片
sw_vers -productVersion; uname -m
# 控制台最後 50 行記錄（貼上前請先檢查有沒有個人資料）
tail -n 50 ~/homeserver/dashboard/panel.log
```

## ⚠️ 法律注意

Shadowrocket 功能本質上是代理伺服器。**在部分國家或地區，架設或使用這類服務可能違法。**
這個功能預設關閉，請先確認你所在地的法律，使用責任由你自行負擔。

## 授權

[MIT](LICENSE)（第三方元件見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)）。AdGuard Home（GPL-3.0）、Xray-core（MPL-2.0）、noVNC（MPL-2.0）、websockify（LGPL-3.0）
不包含在這個專案裡，由安裝程式從官方來源下載，各自依原本的授權使用。

