"""Per-install settings, read from ~/homeserver/config.json (never committed; see config.example.json).

Everything that identifies one household (who owns the panel, which disk is the cloud, launchd label prefix)
lives there, so the code itself can be shared."""
import json
import os

HOME = os.path.expanduser("~")
BASE = os.path.join(HOME, "homeserver")
CONFIG_FILE = os.environ.get("HOMESERVER_CONFIG") or os.path.join(BASE, "config.json")

DEFAULTS = {
    # Tailscale login(s) that own the panel, e.g. "alice@github" or "bob@gmail.com"
    "owners": [],
    # Folder on the external disk used as the family cloud
    "drive_root": "/Volumes/HomeDrive/HomeCloud",
    # Name shown in alerts like "check the cable of <drive_name>"
    "drive_name": "外接硬碟",
    # launchd label prefix of the background services (<prefix>.homepanel, .adguardhome, .xray, .novnc)
    "label_prefix": "local.homeserver",
    # Shadowrocket access through Xray + Tailscale Funnel. Off by default: check the law where you live first.
    "shadowrocket": False,
    # Contact URL (https://… or mailto:…) sent to push services with each Web Push request (required by VAPID)
    "contact": "https://github.com",
    # GitHub repo whose issues appear in 成員 › 回報 (e.g. "you/your-fork"); empty = family reports only
    "github_repo": "",
}


def load():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except FileNotFoundError:
        pass
    if isinstance(cfg["owners"], str):
        cfg["owners"] = [cfg["owners"]]
    return cfg


CFG = load()
OWNERS = set(CFG["owners"])
DRIVE_ROOT = CFG["drive_root"]
DRIVE_NAME = CFG["drive_name"]
LABEL_PREFIX = CFG["label_prefix"]
SHADOWROCKET = bool(CFG["shadowrocket"])
CONTACT = CFG["contact"]
GITHUB_REPO = CFG["github_repo"]
