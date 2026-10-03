# Mac Home Server

[繁體中文](README.md) · **English**

Turn an always-on Mac into your family's network hub: get home with **Tailscale**, **block ads**, run a
**family cloud drive**, and manage it all from a phone **control panel**: who can use what, and for how long.
No coding, no router changes.

> The interface is available in **繁體中文, English, 简体中文, 日本語, 한국어 and Español**. It follows the
> phone's language, or you can pick one with the 🌐 button. It is designed for iPhone and also works on desktop and in dark mode.
> Family guide (Traditional Chinese): <https://hitachi513.github.io/home-guide/>

## Features

| | |
|---|---|
| 🔐 **Get home** | Tailscale VPN; family members can browse through your home connection (exit node) |
| 🛡️ **Ad blocking** | AdGuard Home (3 lists by default, about 400,000 rules), with per-person limits (adult sites, blocked apps). DNS can't block YouTube video ads; use a browser extension for those |
| ☁️ **Family cloud** | An external drive becomes a cloud: personal space with quotas, a shared folder, a 30-day trash, share links (expiry / password / download limit), photo and document previews, iPhone photo auto-backup |
| 👨‍👩‍👧 **Members** | Per-person permissions, expiry date, allowed hours, daily time limit and traffic reports; each person gets their own page |
| 🖥️ **Windows remote** | One command installs a small agent; then your phone shows the PC's status and controls music, volume, notifications, screenshots, lock and shutdown (Tailscale only; no firewall changes) |
| 📱 **Control panel** | Locked with a 4-digit PIN + Face ID, push notifications, Mac health (CPU / memory / battery / trends), speed test, remote control |
| 🔒 **Security monitor** | Security score, 16 health checks, suspicious-event stats, automatic blocking, one-tap “self-attack test” |
| 🔑 **Member page password** | A password on top of the secret address; devices are remembered for 30 days, resetting it signs out every device, wrong guesses lock it |
| 😀 **Personal settings** | Members tap their avatar to set a photo / emoji, a nickname, large text, or change their password |
| 🐞 **Problem reports** | Family members report from their page (with screenshots); GitHub issues are listed in the panel too, where you can change status, reply and label |
| 🌐 **6 languages** | Every screen, push notification, the installer and the Windows agent follow the user's language |
| 🚀 **Shadowrocket** (optional, off by default) | Lets people without Tailscale get home through Shadowrocket ⚠️ see “Legal note” below |

## Requirements

- A Mac that stays on and plugged in (macOS 13 or later, Apple silicon or Intel)
- An external drive for the cloud (optional)
- A [Tailscale](https://tailscale.com/download/mac) account (free), with **MagicDNS** and **HTTPS certificates** turned on in the admin console
  (after installing you also set the global nameserver to this Mac so ad blocking works; the installer tells you how)
- Optional: [Homebrew](https://brew.sh) (only needed for the Shadowrocket feature)

## Install

```bash
git clone https://github.com/Hitachi513/mac-homeserver ~/homeserver
bash ~/homeserver/install.sh
```

The installer speaks your Mac's language. It asks a few questions (which Tailscale account owns the panel,
which disk is the cloud drive, whether to enable Shadowrocket) and then:

1. Downloads and configures AdGuard Home (local only, random admin password)
2. Installs the Python packages (`cryptography`, `cbor2`)
3. Sets up background services that start at boot
4. Publishes the panel with `tailscale serve` (**only your tailnet can reach it**) and member pages with Funnel

Afterwards follow the “Next” steps it prints: open the panel on your iPhone and set a PIN, give Python
“Full Disk Access”, link the Tailscale API (so member permissions apply automatically), and preferably harden the firewall:

```bash
sudo bash ~/homeserver/security/harden.sh
```

All personal settings live in `~/homeserver/config.json` (example: [`config.example.json`](config.example.json)).
To manage GitHub reports in the panel too, add `"github_repo": "you/your-repo"` to config.json (sign in first with `gh auth login`).
Uninstall: `bash ~/homeserver/uninstall.sh` (your data is kept).

## Architecture

```
iPhone ──Tailscale──▶ tailscale serve :443  ──▶ panel    127.0.0.1:8088 (trusts only identities passed by Tailscale)
                      tailscale serve :3443 ──▶ AdGuard  127.0.0.1:3000
anyone ───Funnel────▶ :8443 /p/<secret>     ──▶ member pages 127.0.0.1:8090 (trusts no identity headers)
                      :8443 / (optional)    ──▶ Xray     127.0.0.1:10080 (Shadowrocket)
```

- The server is written with the Python standard library (plus only `cryptography` and `cbor2`); no database, all data is JSON files (mode 600)
- Member permissions are turned into Tailscale ACLs in real time (through the Tailscale API) and revoked automatically on expiry, outside allowed hours, or when the daily time runs out
- Translations: the UI is written in Traditional Chinese and `dashboard/i18n/strings.json` maps every sentence to the other languages. `python3 tools/i18n_extract.py --check` lists anything still missing

## Security

Please read [SECURITY.md](SECURITY.md). In short:

- The panel only accepts connections **forwarded by Tailscale** (it checks which program the connection comes from), so other local programs can't impersonate you
- The only things exposed to the Internet are the member pages (128-bit random address + rate limiting + auto-blocking) and the optional Shadowrocket entrance
- Settings → Security in the panel shows a security score at any time and can run an attack test against itself

## Reporting problems / ideas

| You are… | Where to report |
|---|---|
| 🐞 Hit a bug, install failed, something differs from the docs | [Open a bug report](https://github.com/Hitachi513/mac-homeserver/issues/new?template=bug_report.yml) |
| 💡 Want a feature or an improvement | [Suggest a feature](https://github.com/Hitachi513/mac-homeserver/issues/new?template=feature_request.yml) |
| 🔒 Found a security vulnerability | **Don't post it publicly**; [report it privately](https://github.com/Hitachi513/mac-homeserver/security/advisories/new) |
| 🙋 Not used to GitHub | In your own **control panel → Members → Reports → Report to the system author**: fill in a simple form, personal data is hidden automatically, and one tap opens a pre-filled GitHub page |
| 👨‍👩‍👧 A family member (someone set it up for you) | Tap “Report a problem” on **your page**; it goes straight to the person who set it up |

A free GitHub account is needed. The forms are bilingual (Chinese / English). See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**Before reporting:**
1. [Search the issues](https://github.com/Hitachi513/mac-homeserver/issues?q=is%3Aissue) to see whether it's already reported (if so, add a comment with your details)
2. Update to the latest version and try again: `cd ~/homeserver && git pull`, then restart the panel
3. **Hide personal data**: your Tailscale address (`xxx.ts.net`), IPs, member names, passwords and secret page addresses

**This helps get it fixed faster:**
```bash
# version
cd ~/homeserver && git describe --tags
# macOS version and chip
sw_vers -productVersion; uname -m
# last 50 lines of the panel log (check it for personal data before pasting)
tail -n 50 ~/homeserver/dashboard/panel.log
```

## ⚠️ Legal note

The Shadowrocket feature is a proxy server. **In some countries or regions, running or using such a service may be illegal.**
It is off by default. Check your local laws first; you are responsible for how you use it.

## License

[MIT](LICENSE) (third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)). AdGuard Home (GPL-3.0), Xray-core (MPL-2.0),
noVNC (MPL-2.0) and websockify (LGPL-3.0) are not included in this repository; the installer downloads them from their
official sources and they keep their own licenses.
