# 怎麼回報問題和建議

謝謝你願意花時間回報！這份說明會讓問題更快被修好。

## 我該去哪裡回報？

- 🐞 **Bug／安裝失敗／跟說明不一樣** → [回報問題](https://github.com/Hitachi513/mac-homeserver/issues/new?template=bug_report.yml)
- 💡 **新功能／改進建議** → [建議新功能](https://github.com/Hitachi513/mac-homeserver/issues/new?template=feature_request.yml)
- 🔒 **安全漏洞** → **請不要開公開的 issue**，改用[私下回報](https://github.com/Hitachi513/mac-homeserver/security/advisories/new)（只有維護者看得到）
- 👨‍👩‍👧 **你是某個家庭的成員**（不是自己架的）→ 在你的專屬網頁按「回報問題」，問題會送給幫你架設的人，他看完如果是程式的 bug 會再回報到這裡

## 回報之前

1. **先搜尋**：到 [Issues](https://github.com/Hitachi513/mac-homeserver/issues?q=is%3Aissue) 用關鍵字找找看。有人回報過的話，在那一則留言補充你的情況就好，不用另外開
2. **先更新**：
   ```bash
   cd ~/homeserver && git pull
   launchctl kickstart -k gui/$(id -u)/$(python3 -c 'import json;print(json.load(open("config.json"))["label_prefix"])').homepanel
   ```
   很多問題在新版已經修好了
3. **遮掉個人資料**（很重要，issue 是公開的，所有人都看得到）：
   - Tailscale 網址：`你的電腦名.xxxx.ts.net` → 改成 `my-mac.example.ts.net`
   - IP 位址（`100.x.x.x`、`192.168.x.x`、對外 IP）
   - 成員的名字、email、專屬網址（`/p/一長串英數字/`）、密碼
   - 截圖裡的這些資訊也要塗掉

## 一個好的回報包含

- **發生什麼事**：你看到什麼？原本以為會怎樣？
- **怎麼重現**：一步一步寫，例如「1. 打開控制台 → 雲端　2. 上傳一張 HEIC 照片　3. 出現錯誤」
- **版本和環境**：
  ```bash
  cd ~/homeserver && git describe --tags     # 你用的版本
  sw_vers -productVersion; uname -m          # macOS 版本、晶片（arm64 = Apple 晶片）
  ```
  還有你用什麼裝置看到問題（例如 iPhone 15 Safari、電腦版 Chrome）
- **記錄檔**（選填）：
  ```bash
  tail -n 50 ~/homeserver/dashboard/panel.log
  ```
  貼上前請先看一遍，把個人資料遮掉
- **截圖**：可以直接拖進 GitHub 的輸入框

## 之後會怎樣

- 維護者會在 issue 裡回覆，可能會問你更多細節（標上「需要更多資訊」時，請記得回來看）
- 修好之後 issue 會被關閉，修正會放進下一個版本，可以在 [Releases](https://github.com/Hitachi513/mac-homeserver/releases) 和 [CHANGELOG.md](CHANGELOG.md) 看到
- 這是個人維護的專案，回覆可能需要幾天，請見諒 🙏

## 想自己修？

歡迎發 Pull Request！請：
- 一個 PR 只修一件事，說明改了什麼、為什麼
- 不要把任何個人資料、`config.json`、成員資料放進去（`.gitignore` 預設會擋）
- 介面文字用繁體中文寫；改完執行 `python3 tools/i18n_extract.py`，再把新句子的翻譯補進 `dashboard/i18n/strings.json`（`--check` 會列出還缺的）

---

## English

Thanks for taking the time to report! Where to go:

- 🐞 **Bug / install failed / differs from the docs** → [bug report](https://github.com/Hitachi513/mac-homeserver/issues/new?template=bug_report.yml)
- 💡 **Feature or improvement** → [feature request](https://github.com/Hitachi513/mac-homeserver/issues/new?template=feature_request.yml)
- 🔒 **Security vulnerability** → **don't open a public issue**; use a [private report](https://github.com/Hitachi513/mac-homeserver/security/advisories/new) (only maintainers can see it)
- 🙋 **Not used to GitHub?** In your control panel → Members → Reports → **Report to the system author**: it collects the details, hides personal data and opens a pre-filled page

**Before reporting:** search the [issues](https://github.com/Hitachi513/mac-homeserver/issues?q=is%3Aissue); update with `cd ~/homeserver && git pull` and restart the panel;
and **hide personal data** (issues are public): your `*.ts.net` address, IPs, member names and emails, secret page addresses (`/p/…/`), passwords, including in screenshots.

**A good report has:** what happened vs. what you expected; steps to reproduce; your version (`git describe --tags`), macOS and chip (`sw_vers -productVersion; uname -m`)
and the device/browser; optionally the last lines of `~/homeserver/dashboard/panel.log` (check for personal data first) and screenshots.

**Pull requests** are welcome: one change per PR, explain what and why, never commit personal data (`.gitignore` is an allow-list).
UI text is written in Traditional Chinese; run `python3 tools/i18n_extract.py` and add the translations for new sentences to
`dashboard/i18n/strings.json` (`--check` lists what's missing).
