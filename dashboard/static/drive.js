// Cloud drive browser shared by the owner panel, the member portal and public share pages.
// new DriveUI(el, { url(op, params) -> string, headers, icon, esc, fmtB, toast, badge, readonly, onLocked, onShared, share })
(function () {
  const KIND = { folder: ["folder", "#32ade6"], image: ["image", "#ff375f"], video: ["film", "#bf5af2"], audio: ["music", "#ff9f0a"],
    pdf: ["file", "#ff453a"], doc: ["file", "#0a84ff"], text: ["code", "#5e5ce6"], archive: ["archive", "#8e8e93"], file: ["file", "#8e8e93"] };
  const VISUAL = k => k === "image" || k === "video";
  const PREVIEW = k => ["image", "video", "audio", "pdf", "doc", "text"].includes(k);
  const TEXTUTIL = /\.(docx?|rtf|odt)$/i;
  const SORTS = [["name", "名稱"], ["ctime", "上傳時間"], ["mtime", "修改時間"], ["size", "大小"], ["kind", "類型"]];
  const coll = new Intl.Collator("zh-Hant", { numeric: true, sensitivity: "base" });

  const pad = n => String(n).padStart(2, "0");
  function when(t) {
    if (!t) return "—";
    const d = new Date(t * 1000), now = new Date(), hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const day = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((day(now) - day(d)) / 864e5);
    if (diff === 0) return "今天 " + hm;
    if (diff === 1) return "昨天 " + hm;
    if (d.getFullYear() === now.getFullYear()) return `${d.getMonth() + 1}/${d.getDate()} ${hm}`;
    return `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()}`;
  }
  const full = t => t ? new Date(t * 1000).toLocaleString(I18N.locale, { year: "numeric", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }) : "—";
  const dur = s => { if (!isFinite(s)) return "—"; s = Math.round(s); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return (h ? h + ":" + pad(m) : m) + ":" + pad(s % 60); };
  const ls = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } };

  // tiny CSV parser (quotes, commas inside quotes, CRLF)
  function csv(text, sep) {
    const rows = []; let row = [], cell = "", q = false;
    for (let i = 0; i < text.length && rows.length < 300; i++) {
      const c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; continue; }
      if (c === '"') q = true; else if (c === sep) { row.push(cell); cell = ""; }
      else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cell); rows.push(row); row = []; cell = ""; }
      else cell += c;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows;
  }

  class DriveUI {
    constructor(el, o) {
      this.el = el; this.o = o; this.path = null; this.roots = []; this.items = []; this.mode = "browse";
      this.cache = {};  // path -> last listing, so going back into a folder is instant
      this.view = ls("drvView") || "list";
      try { this.sort = JSON.parse(ls("drvSort")) || { by: "name", desc: false }; } catch { this.sort = { by: "name", desc: false }; }
      this.sel = new Set(); this.selecting = false;
      const I = o.icon, ro = !!o.readonly;
      el.innerHTML = `
        <div class="drv-bar">
          <div class="drv-crumbs"></div>
          <div class="drv-actions">
            <button class="btn sm iconbtn" data-a="search" aria-label="搜尋" title="搜尋">${I("search")}</button>
            <button class="btn sm iconbtn" data-a="sort" aria-label="排序" title="排序">${I("sort")}</button>
            <button class="btn sm iconbtn" data-a="view" aria-label="切換顯示方式" title="切換顯示方式">${I(this.view === "grid" ? "list" : "grid")}</button>
            ${ro ? "" : `<button class="btn sm iconbtn" data-a="trash" aria-label="垃圾桶" title="垃圾桶">${I("trash")}</button>`}
          </div>
        </div>
        <div class="drv-search" hidden><input type="search" placeholder="搜尋檔名…" autocapitalize="off" autocorrect="off"></div>
        <div class="drv-tools" hidden>
          <button class="btn sm" data-a="select">${I("check")}選取</button>
          <button class="btn sm" data-a="mkdir">${I("folderplus")}新資料夾</button>
          <label class="btn sm primary" data-a="upload">${I("upload")}上傳<input type="file" multiple hidden></label>
        </div>
        <div class="drv-selbar" hidden>
          <span class="drv-selcount">點檔案來選取</span>
          <button class="btn sm" data-s="all">全選</button>
          <button class="btn sm" data-s="move" disabled>${I("move")}移動</button>
          <button class="btn sm danger" data-s="delete" disabled>${I("trash")}刪除</button>
          <button class="btn sm primary" data-s="done">完成</button>
        </div>
        <div class="drv-quota"></div>
        <div class="drv-prog" hidden><div class="progress"><i></i></div><div class="small muted drv-progtext"></div></div>
        <div class="drv-list"></div>`;
      // the viewer lives on <body>: inside a glass card (backdrop-filter) a position:fixed overlay is clipped to the card
      this.viewer = document.createElement("div");
      this.viewer.className = "modal drv-viewer"; this.viewer.hidden = true;
      this.viewer.innerHTML = `<div class="drv-view-box"><div class="drv-view-body"></div><div class="btns drv-view-btns"></div></div>`;
      document.body.appendChild(this.viewer);
      this.$ = s => el.querySelector(s) || this.viewer.querySelector(s);
      this.$(".drv-list").addEventListener("click", e => this.onClick(e));
      this.$(".drv-crumbs").addEventListener("click", e => { const b = e.target.closest("[data-go]"); if (b) { this.mode = "browse"; this.open(b.dataset.go); } });
      this.$('[data-a="mkdir"]').onclick = () => this.mkdir();
      this.$('[data-a="upload"] input').onchange = e => this.upload([...e.target.files]).then(() => e.target.value = "");
      this.$('[data-a="view"]').onclick = () => this.toggleView();
      this.$('[data-a="search"]').onclick = () => this.toggleSearch();
      this.$('[data-a="sort"]').onclick = () => this.sortSheet();
      this.$('[data-a="select"]').onclick = () => this.setSelecting(true);
      this.$(".drv-selbar").onclick = e => this.selAction(e);
      if (!ro) this.$('[data-a="trash"]').onclick = () => this.openTrash();
      let st; this.$(".drv-search input").oninput = e => { clearTimeout(st); st = setTimeout(() => this.search(e.target.value), 250); };
      el.addEventListener("dragover", e => { if (this.writable) { e.preventDefault(); el.classList.add("drv-drag"); } });
      el.addEventListener("dragleave", () => el.classList.remove("drv-drag"));
      el.addEventListener("drop", e => { el.classList.remove("drv-drag"); if (this.writable) { e.preventDefault(); this.upload([...e.dataTransfer.files]); } });
      this.viewer.addEventListener("click", e => { if (e.target === this.viewer) this.closeViewer(); });
      // swipe left/right between previews
      let sx = null, sy = null;
      this.viewer.addEventListener("touchstart", e => { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, { passive: true });
      this.viewer.addEventListener("touchend", e => {
        if (sx == null || !this.cur) return; const dx = e.changedTouches[0].clientX - sx, dy = e.changedTouches[0].clientY - sy; sx = null;
        if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5 && !e.target.closest(".drv-doc")) this.step(dx < 0 ? 1 : -1);
      });
      document.addEventListener("keydown", e => { if (this.viewer.hidden || !this.cur) return; if (e.key === "ArrowRight") this.step(1); if (e.key === "ArrowLeft") this.step(-1); if (e.key === "Escape") this.closeViewer(); });
    }

    async req(op, params, opts = {}) {
      const r = await fetch(this.o.url(op, params), { ...opts, headers: { ...(opts.headers || {}), ...(this.o.headers || {}) } });
      const d = await r.json().catch(() => ({ ok: false, error: "HTTP " + r.status }));
      if (d.locked && this.o.onLocked) this.o.onLocked();
      if (!r.ok || d.ok === false) throw new Error(d.error || "HTTP " + r.status);
      return d;
    }
    post(op, body) { return this.req(op, {}, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }

    async start(pre) {
      try {
        const d = pre || await this.req("roots", {});
        if (!d.mounted) { this.$(".drv-list").innerHTML = `<div class="empty">${this.o.icon("alert")} 外接硬碟沒有接上</div>`; return; }
        this.roots = d.roots;
        this.open(this.path || "/");
      } catch (e) { this.$(".drv-list").innerHTML = `<div class="empty">${this.o.esc(e.message)}</div>`; }
    }

    rootLabel(key) { return (this.roots.find(r => r.key === key) || {}).label || key; }
    niceDir(path) { const p = path.split("/").filter(Boolean); return p.length ? [this.rootLabel(p[0]), ...p.slice(1)].join(" › ") : "最上層"; }

    crumbs(extra) {
      const { esc } = this.o, parts = this.path.split("/").filter(Boolean);
      let html = `<button class="drv-crumb" data-go="/" aria-label="最上層">${this.o.icon("home")}</button>`, acc = "";
      parts.forEach((p, i) => {
        acc += "/" + p;
        html += `<span class="drv-sep">›</span><button class="drv-crumb" data-go="${esc(acc)}">${esc(i === 0 ? this.rootLabel(p) : p)}</button>`;
      });
      if (extra) html += `<span class="drv-sep">›</span><span class="drv-crumb">${esc(extra)}</span>`;
      const c = this.$(".drv-crumbs"), bar = this.$(".drv-bar"); c.innerHTML = html;
      bar.classList.remove("long");
      if (c.scrollWidth > c.clientWidth + 2) bar.classList.add("long");  // path too long for one line: give it its own row
      c.scrollLeft = c.scrollWidth;
    }

    quota(root) {
      const q = this.$(".drv-quota");
      if (!root || !root.quota) { q.innerHTML = ""; return; }
      const pct = Math.min(100, root.used / root.quota * 100);
      q.innerHTML = `<div class="small muted">已用 ${this.o.fmtB(root.used)} / ${this.o.fmtB(root.quota)}</div>
        <div class="meter" style="--c:${pct > 90 ? "#ff453a" : "#0a84ff"}"><i style="width:${pct.toFixed(1)}%"></i></div>`;
    }

    toggleActions() {
      const can = this.writable && this.mode === "browse";
      if (!can && this.selecting) this.setSelecting(false);
      this.$(".drv-tools").hidden = !can || this.selecting;
      this.$('[data-a="sort"]').hidden = this.mode === "trash" || this.path === "/" && this.mode === "browse";
    }

    toggleView() {
      this.view = this.view === "grid" ? "list" : "grid";
      ls("drvView", this.view);
      this.$('[data-a="view"]').innerHTML = this.o.icon(this.view === "grid" ? "list" : "grid");
      if (this.mode === "browse" && this.path !== "/") this.renderItems(); else if (this.mode === "search") this.renderItems(true);
    }

    toggleSearch() {
      const box = this.$(".drv-search"); box.hidden = !box.hidden;
      if (!box.hidden) { box.querySelector("input").focus(); } else { box.querySelector("input").value = ""; this.mode = "browse"; this.open(this.path || "/"); }
    }

    // ---------- sorting ----------
    sorted(items) {
      const { by, desc } = this.sort, k = x => by === "ctime" ? (x.ctime || x.mtime) : x[by];
      const f = by === "name" ? (a, b) => coll.compare(a.name, b.name)
        : by === "kind" ? (a, b) => coll.compare(a.kind, b.kind) || coll.compare(a.name, b.name)
        : (a, b) => (k(a) || 0) - (k(b) || 0) || coll.compare(a.name, b.name);
      return items.slice().sort((a, b) => (b.dir - a.dir) || (desc ? -f(a, b) : f(a, b)));
    }

    sortSheet() {
      const { icon } = this.o, s = this.sort;
      this.cur = null;
      this.$(".drv-view-body").innerHTML = `<div class="drv-sheet drv-share">${this.o.badge("sort", "#0a84ff", "drv-ic")}<div class="t">排序方式</div>
        <div class="drv-form">
          <div class="k">依照</div><div class="chipbtns" data-g="by">${SORTS.map(([v, l]) => `<button class="chipbtn ${s.by === v ? "on" : ""}" data-v="${v}">${l}</button>`).join("")}</div>
          <div class="k">順序</div><div class="chipbtns" data-g="desc"><button class="chipbtn ${!s.desc ? "on" : ""}" data-v="0">由小到大・舊到新</button><button class="chipbtn ${s.desc ? "on" : ""}" data-v="1">由大到小・新到舊</button></div>
        </div><div class="s" style="margin-top:10px">資料夾一律排在最前面</div></div>`;
      const box = this.$(".drv-view-btns");
      box.innerHTML = `<button class="btn primary" data-m="close">${icon("tick")}完成</button>`;
      box.onclick = e => { if (e.target.closest('[data-m="close"]')) this.closeViewer(); };
      this.$(".drv-view-body").onclick = e => {
        const b = e.target.closest(".chipbtn"); if (!b) return;
        const g = b.parentElement.dataset.g;
        b.parentElement.querySelectorAll(".chipbtn").forEach(x => x.classList.toggle("on", x === b));
        if (g === "by") { this.sort.by = b.dataset.v; if (b.dataset.v === "ctime" || b.dataset.v === "mtime" || b.dataset.v === "size") this.sort.desc = true; else this.sort.desc = false;
          this.$('[data-g="desc"]').querySelectorAll(".chipbtn").forEach(x => x.classList.toggle("on", (x.dataset.v === "1") === this.sort.desc)); }
        else this.sort.desc = b.dataset.v === "1";
        ls("drvSort", JSON.stringify(this.sort));
        this.items = this.sorted(this.items); this.renderItems(this.mode === "search");
      };
      this.viewer.hidden = false;
    }

    async search(q) {
      if (!q.trim()) { this.mode = "browse"; return this.open(this.path || "/"); }
      this.mode = "search"; this.toggleActions(); this.crumbs("搜尋「" + q + "」");
      try { const d = await this.req("search", { q }); this.items = this.sorted(d.items); this.renderItems(true, d.more); }
      catch (e) { this.$(".drv-list").innerHTML = `<div class="empty">${this.o.esc(e.message)}</div>`; }
    }

    async open(path) {
      this.path = path || "/"; this.mode = "browse"; this.sel.clear();
      this.crumbs();
      const list = this.$(".drv-list");
      if (this.path === "/") {
        this.writable = false; this.toggleActions(); this.quota(null);
        list.innerHTML = this.roots.map(r => `<button class="drv-item" data-open="/${r.key}">
          ${this.o.badge("folder", r.key === "shared" ? "#30d158" : r.key === "mac" ? "#8e8e93" : "#32ade6", "drv-ic")}
          <span class="drv-name"><span class="t">${this.o.esc(r.label)}</span>${r.desc ? `<span class="s drv-desc">${this.o.esc(r.desc)}</span>` : ""}<span class="s">${r.writable ? "" : "只能看・"}已用 ${this.o.fmtB(r.used)}${r.quota ? " / " + this.o.fmtB(r.quota) : ""}</span></span>
          <span class="drv-chev">›</span></button>`).join("") || `<div class="empty">沒有可用的資料夾</div>`;
        return;
      }
      const want = this.path, hit = this.cache[want];
      const show = d => { this.items = this.sorted(d.items); this.writable = d.writable && !this.o.readonly; this.toggleActions(); this.quota(d.root); this.renderItems(); };
      if (hit) show(hit); else list.innerHTML = `<div class="skel"><i></i><i></i><i></i></div>`;
      try {
        const d = await this.req("list", { path: want });
        this.cache[want] = d;
        if (this.path === want && this.mode === "browse" && JSON.stringify(d) !== JSON.stringify(hit)) show(d);
      } catch (e) { if (!hit) list.innerHTML = `<div class="empty">${this.o.esc(e.message)}</div>`; }
    }

    itemPath(it) { return it.path || this.path.replace(/\/$/, "") + "/" + it.name; }
    thumbUrl(it, big) { return this.o.url("thumb", { path: this.itemPath(it), ...(big ? { size: "big" } : {}) }); }

    renderItems(searching, more) {
      const { esc, fmtB, icon } = this.o;
      const list = this.$(".drv-list");
      if (!this.items.length) {
        list.innerHTML = `<div class="empty">${searching ? "找不到符合的檔案" : this.writable ? "這裡是空的，按「上傳」加入檔案" : "這裡是空的"}</div>`;
        return;
      }
      const files = this.items.filter(x => !x.dir), total = files.reduce((a, x) => a + x.size, 0);
      const foot = `<div class="small muted drv-foot">${this.items.length - files.length ? (this.items.length - files.length) + " 個資料夾・" : ""}${files.length} 個檔案${files.length ? "・共 " + fmtB(total) : ""}${more ? "・只顯示前 200 筆" : ""}</div>`;
      const selc = i => this.selecting ? (this.sel.has(i) ? " sel" : "") + " selecting" : "";
      const check = i => this.selecting ? `<span class="drv-check">${this.sel.has(i) ? icon("tick") : ""}</span>` : "";
      if (this.view === "grid") {
        list.innerHTML = `<div class="drv-grid">${this.items.map((it, i) => {
          const [ic, c] = KIND[it.kind] || KIND.file;
          const pic = VISUAL(it.kind) || it.kind === "pdf" || it.kind === "doc" ? `<img loading="lazy" src="${esc(this.thumbUrl(it))}" alt="" onerror="this.remove()">` : "";
          return `<button class="drv-cell${selc(i)}" data-i="${i}" aria-label="${esc(it.name)}">${pic}<span class="drv-cell-ic">${this.o.badge(ic, c, "drv-ic")}</span>
            ${it.kind === "video" ? `<span class="drv-play">${icon("play")}</span>` : ""}${check(i)}
            <span class="drv-cell-name">${esc(it.name)}</span></button>`;
        }).join("")}</div>${foot}`;
        return;
      }
      list.innerHTML = this.items.map((it, i) => {
        const [ic, c] = KIND[it.kind] || KIND.file;
        const t = this.sort.by === "mtime" ? when(it.mtime) + " 修改" : when(it.ctime || it.mtime) + (it.dir ? " 建立" : " 上傳");
        const sub = (searching ? esc(it.folder) + "・" : "") + (it.dir ? "資料夾" : fmtB(it.size)) + "・" + t;
        return `<div class="drv-item${selc(i)}" data-i="${i}">${check(i)}
          ${VISUAL(it.kind) ? `<span class="drv-thumb">${this.o.badge(ic, c, "drv-ic")}<img loading="lazy" src="${esc(this.thumbUrl(it))}" alt="" onerror="this.remove()"></span>` : this.o.badge(ic, c, "drv-ic")}
          <span class="drv-name"><span class="t">${esc(it.name)}</span><span class="s">${sub}</span></span>
          ${this.selecting ? "" : `<button class="drv-more" data-more="${i}" aria-label="更多">${icon("more")}</button>`}</div>`;
      }).join("") + foot;
    }

    onClick(e) {
      const open = e.target.closest("[data-open]");
      if (open) return this.open(open.dataset.open);
      const tr = e.target.closest("[data-tr]");
      if (tr) return this.trashAction(tr.dataset.tr, tr.dataset.id, tr);
      const more = e.target.closest("[data-more]");
      if (more) { e.stopPropagation(); return this.menu(this.items[+more.dataset.more]); }
      const row = e.target.closest("[data-i]");
      if (!row || this.mode === "trash") return;
      const i = +row.dataset.i, it = this.items[i];
      if (this.selecting) { this.sel.has(i) ? this.sel.delete(i) : this.sel.add(i); this.renderItems(); this.selCount(); return; }
      if (it.dir) { this.$(".drv-search").hidden = true; this.$(".drv-search input").value = ""; this.open(this.itemPath(it)); }
      else if (PREVIEW(it.kind)) this.viewItem(it);
      else this.menu(it);
    }

    // ---------- multi-select ----------
    setSelecting(on) {
      this.selecting = on; this.sel.clear();
      this.$(".drv-selbar").hidden = !on; this.$(".drv-tools").hidden = on || !(this.writable && this.mode === "browse");
      this.selCount(); this.renderItems();
    }
    selCount() {
      const n = this.sel.size;
      this.$(".drv-selcount").textContent = n ? `已選 ${n} 個` : "點檔案來選取";
      this.$('[data-s="move"]').disabled = this.$('[data-s="delete"]').disabled = !n;
      const del = this.$('[data-s="delete"]'); del.dataset.confirm = ""; del.innerHTML = this.o.icon("trash") + "刪除";
      this.$('[data-s="all"]').textContent = n === this.items.length && n ? "全不選" : "全選";
    }
    async selAction(e) {
      const b = e.target.closest("[data-s]"); if (!b) return;
      const s = b.dataset.s, picked = [...this.sel].map(i => this.items[i]);
      if (s === "done") return this.setSelecting(false);
      if (s === "all") { if (this.sel.size === this.items.length) this.sel.clear(); else this.items.forEach((_, i) => this.sel.add(i)); this.renderItems(); return this.selCount(); }
      if (s === "move") return this.pickFolder(picked);
      if (s === "delete") {
        if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.innerHTML = this.o.icon("trash") + `確定刪除 ${picked.length} 個？`; return; }
        let ok = 0;
        for (const it of picked) { try { await this.post("delete", { path: this.itemPath(it) }); ok++; } catch (err) { this.o.toast(it.name + "：" + err.message, "alert"); } }
        if (ok) this.o.toast(`已把 ${ok} 個項目移到垃圾桶（30 天內可以還原）`, "ok");
        this.setSelecting(false); this.refresh();
      }
    }

    // pick a destination folder, then move `items` there
    pickFolder(items) {
      const { esc, icon } = this.o;
      const from = new Set(items.map(it => this.itemPath(it)));
      const srcDir = this.itemPath(items[0]).replace(/\/[^/]+$/, "");
      let at = this.path.startsWith("/") && this.path !== "/" ? srcDir : "/";
      const body = this.$(".drv-view-body"), box = this.$(".drv-view-btns");
      const draw = async () => {
        body.innerHTML = `<div class="drv-sheet drv-pick"><div class="t">移動 ${items.length === 1 ? "「" + esc(items[0].name) + "」" : items.length + " 個項目"} 到…</div>
          <div class="drv-pick-at">${icon("folder")} ${esc(this.niceDir(at))}</div><div class="drv-pick-list"><div class="skel"><i></i><i></i></div></div></div>`;
        box.innerHTML = `${at !== "/" ? `<button class="btn" data-up>${icon("chevl")}上一層</button>` : ""}
          <button class="btn primary" data-here ${at === "/" || at === srcDir ? "disabled" : ""}>${icon("move")}移到這裡</button><button class="btn" data-m="close">取消</button>`;
        let rows = [];
        try {
          if (at === "/") rows = this.roots.filter(r => r.writable).map(r => ({ path: "/" + r.key, name: r.label }));
          else rows = (await this.req("list", { path: at })).items.filter(x => x.dir).map(x => ({ path: at + "/" + x.name, name: x.name })).filter(x => !from.has(x.path));
        } catch (err) { rows = []; }
        body.querySelector(".drv-pick-list").innerHTML = rows.length ? rows.map(r => `<button class="drv-item" data-to="${esc(r.path)}">${this.o.badge("folder", "#32ade6", "drv-ic")}
          <span class="drv-name"><span class="t">${esc(r.name)}</span></span><span class="drv-chev">›</span></button>`).join("") : `<div class="small muted" style="padding:10px">沒有其他資料夾</div>`;
      };
      body.onclick = e => { const t = e.target.closest("[data-to]"); if (t) { at = t.dataset.to; draw(); } };
      box.onclick = async e => {
        if (e.target.closest('[data-m="close"]')) return this.closeViewer();
        if (e.target.closest("[data-up]")) { at = at.split("/").filter(Boolean).length <= 1 ? "/" : at.replace(/\/[^/]+$/, ""); return draw(); }
        if (e.target.closest("[data-here]")) {
          try { const d = await this.post("move", { paths: [...from], dest: at }); this.o.toast(`已移動 ${d.moved} 個項目到「${this.niceDir(at)}」`, "ok"); this.cache = {}; this.closeViewer(); this.setSelecting(false); this.refresh(); }
          catch (err) { this.o.toast(err.message, "alert"); }
        }
      };
      this.cur = null; this.viewer.hidden = false; draw();
    }

    fileUrl(it, inline) { return this.o.url("get", { path: this.itemPath(it), ...(inline ? { inline: "1" } : {}) }); }

    step(d) {
      const vis = this.items.filter(x => !x.dir && PREVIEW(x.kind));
      const i = vis.indexOf(this.cur); if (i < 0) return;
      const n = vis[(i + d + vis.length) % vis.length]; if (n && n !== this.cur) this.viewItem(n);
    }

    async textView(it, body) {
      const { esc } = this.o;
      body.innerHTML = `<div class="drv-doc"><div class="skel"><i></i><i></i><i></i></div></div>`;
      try {
        const d = await this.req("text", { path: this.itemPath(it) });
        if (this.cur !== it) return;
        let html;
        const ext = d.ext;
        if ((ext === "csv" || ext === "tsv") && d.text.trim()) {
          const rows = csv(d.text, ext === "tsv" ? "\t" : (d.text.split("\n")[0].split(";").length > d.text.split("\n")[0].split(",").length ? ";" : ","));
          html = `<div class="drv-table"><table>${rows.map((r, i) => `<tr>${r.map(c => i ? `<td>${esc(c)}</td>` : `<th>${esc(c)}</th>`).join("")}</tr>`).join("")}</table></div>
            ${rows.length >= 300 ? `<div class="small muted">只顯示前 300 列</div>` : ""}`;
        } else {
          let t = d.text;
          if (ext === "json") { try { t = JSON.stringify(JSON.parse(t), null, 2); } catch {} }
          html = `<pre>${esc(t) || "（空白檔案）"}</pre>`;
        }
        body.querySelector(".drv-doc").innerHTML = html + (d.truncated ? `<div class="small muted" style="padding:8px 0 0">檔案太大，只顯示前 256 KB，完整內容請下載</div>` : "");
      } catch (e) { body.querySelector(".drv-doc").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    }

    viewItem(it) {
      const { esc, icon } = this.o, src = this.fileUrl(it, true);
      if (!PREVIEW(it.kind)) return this.menu(it);
      this.cur = it;
      const body = this.$(".drv-view-body"); body.onclick = null;
      const name = `<div class="drv-view-name">${esc(it.name)}<span>${it.size ? " ・" + this.o.fmtB(it.size) : ""}</span></div>`;
      const extra = [];
      if (it.kind === "image") {
        body.innerHTML = `<img alt="">` + name;
        const img = body.querySelector("img");
        img.onerror = () => { if (!img.dataset.f) { img.dataset.f = "1"; img.src = this.thumbUrl(it, true); } };  // e.g. HEIC outside Safari
        img.src = src;
      } else if (it.kind === "video") body.innerHTML = `<video src="${esc(src)}" controls playsinline autoplay></video>` + name;
      else if (it.kind === "audio") body.innerHTML = `<div class="drv-audio">${this.o.badge("music", "#ff9f0a", "drv-ic")}<div class="t">${esc(it.name)}</div><audio src="${esc(src)}" controls autoplay></audio></div>`;
      else if (it.kind === "text") { this.textView(it, body); body.insertAdjacentHTML("beforeend", name); }
      else {  // pdf / office: Quick Look renders the first page on the Mac
        body.innerHTML = `<div class="drv-page"><img alt="" src="${esc(this.thumbUrl(it, true))}"><div class="small muted drv-page-note">第一頁預覽${it.kind === "pdf" ? "・按「打開 PDF」看全部" : "・下載後可以看完整內容"}</div></div>` + name;
        body.querySelector("img").onerror = () => { body.querySelector(".drv-page").innerHTML = `<div class="drv-sheet">${this.o.badge("file", "#0a84ff", "drv-ic")}<div class="t">${esc(it.name)}</div><div class="s">這個檔案沒辦法預覽，請下載後打開</div></div>`; };
        if (it.kind === "pdf") extra.push(`<a class="btn" href="${esc(src)}" target="_blank" rel="noopener">${icon("file")}打開 PDF</a>`);
        if (TEXTUTIL.test(it.name)) extra.push(`<button class="btn" data-txt>${icon("code")}看文字</button>`);
      }
      const many = this.items.filter(x => !x.dir && PREVIEW(x.kind)).length > 1;
      const box = this.$(".drv-view-btns");
      box.innerHTML = (many ? `<button class="btn iconbtn" data-nav="-1" aria-label="上一個">${icon("chevl")}</button>` : "") + extra.join("") +
        `<a class="btn" href="${esc(this.fileUrl(it))}">${icon("download")}下載</a>` +
        `<button class="btn" data-m="more">${icon("more")}更多</button>` +
        `<button class="btn iconbtn" data-close aria-label="關閉">${icon("x")}</button>` +
        (many ? `<button class="btn iconbtn" data-nav="1" aria-label="下一個">${icon("chevr")}</button>` : "");
      box.onclick = e => {
        const b = e.target.closest("button"); if (!b) return;
        if (b.dataset.nav) return this.step(+b.dataset.nav);
        if (b.dataset.close !== undefined) return this.closeViewer();
        if (b.dataset.txt !== undefined) { b.remove(); this.textView(it, body); return; }
        if (b.dataset.m === "more") return this.menu(it);
      };
      this.viewer.hidden = false;
    }
    closeViewer() { this.viewer.hidden = true; this.cur = null; this.$(".drv-view-body").innerHTML = ""; this.$(".drv-view-body").onclick = null; }

    menu(it) {
      const { esc, icon } = this.o;
      this.cur = null;
      const btns = [];
      if (!it.dir && PREVIEW(it.kind)) btns.push(`<button class="btn" data-m="view">${icon("image")}預覽</button>`);
      btns.push(it.dir ? `<a class="btn" href="${esc(this.o.url("zip", { path: this.itemPath(it) }))}">${icon("download")}下載 ZIP</a>`
        : `<a class="btn" href="${esc(this.fileUrl(it))}">${icon("download")}下載</a>`);
      btns.push(`<button class="btn" data-m="info">${icon("info")}詳細資訊</button>`);
      const canShare = !this.o.readonly && this.o.share !== false && (!this.o.shareRoots || this.o.shareRoots.includes(this.itemPath(it).split("/")[1]));
      if (canShare) btns.push(`<button class="btn" data-m="share">${icon("link")}分享</button>`);
      if (this.writable || (this.mode === "search" && !this.o.readonly)) btns.push(`<button class="btn" data-m="rename">${icon("edit")}改名</button>`, `<button class="btn" data-m="move">${icon("move")}移動</button>`, `<button class="btn danger" data-m="delete">${icon("trash")}刪除</button>`);
      btns.push(`<button class="btn" data-m="close">${icon("x")}關閉</button>`);
      const body = this.$(".drv-view-body"); body.onclick = null;
      body.innerHTML = `<div class="drv-sheet">${it.kind === "image" || it.kind === "video" ? `<img class="drv-sheet-pic" alt="" src="${esc(this.thumbUrl(it))}" onerror="this.remove()">` : this.o.badge((KIND[it.kind] || KIND.file)[0], (KIND[it.kind] || KIND.file)[1], "drv-ic")}
        <div class="t">${esc(it.name)}</div><div class="s">${it.dir ? "資料夾" : this.o.fmtB(it.size)}・${when(it.ctime || it.mtime)}${it.dir ? " 建立" : " 上傳"}</div></div>`;
      const box = this.$(".drv-view-btns"); box.innerHTML = btns.join("");
      box.onclick = async e => {
        const m = e.target.closest("[data-m]"); if (!m) return;
        if (m.dataset.m === "close") return this.closeViewer();
        if (m.dataset.m === "view") return this.viewItem(it);
        if (m.dataset.m === "info") return this.infoSheet(it);
        if (m.dataset.m === "share") return this.shareForm(it);
        if (m.dataset.m === "move") return this.pickFolder([it]);
        if (m.dataset.m === "rename") {
          box.innerHTML = `<input type="text" class="drv-input" value="${esc(it.name)}"><button class="btn primary" data-ok>確定</button><button class="btn" data-m="close">取消</button>`;
          const inp = box.querySelector("input"); inp.focus(); inp.setSelectionRange(0, it.dir || !it.name.includes(".") ? it.name.length : it.name.lastIndexOf("."));
          box.querySelector("[data-ok]").onclick = async () => {
            try { await this.post("rename", { path: this.itemPath(it), name: inp.value.trim() }); this.o.toast("已改名", "ok"); this.closeViewer(); this.refresh(); }
            catch (err) { this.o.toast(err.message, "alert"); }
          };
          return;
        }
        if (m.dataset.m === "delete") {
          if (m.dataset.confirm !== "1") { m.dataset.confirm = "1"; m.innerHTML = icon("trash") + "確定移到垃圾桶？"; return; }
          try { await this.post("delete", { path: this.itemPath(it) }); this.o.toast("已移到垃圾桶（30 天內可以還原）", "ok"); this.closeViewer(); this.refresh(); }
          catch (err) { this.o.toast(err.message, "alert"); }
        }
      };
      this.viewer.hidden = false;
    }

    async infoSheet(it) {
      const { esc, icon, fmtB } = this.o, path = this.itemPath(it);
      const body = this.$(".drv-view-body"), box = this.$(".drv-view-btns");
      const [ic, c] = KIND[it.kind] || KIND.file;
      body.innerHTML = `<div class="drv-sheet drv-info">${this.o.badge(ic, c, "drv-ic")}<div class="t">${esc(it.name)}</div><div class="drv-kv"><div class="skel"><i></i><i></i><i></i></div></div></div>`;
      box.innerHTML = `<button class="btn" data-back>${icon("chevl")}返回</button><button class="btn" data-m="close">${icon("x")}關閉</button>`;
      box.onclick = e => { if (e.target.closest("[data-back]")) this.menu(it); if (e.target.closest('[data-m="close"]')) this.closeViewer(); };
      this.viewer.hidden = false;
      try {
        const d = await this.req("info", { path });
        const rows = [["類型", d.type + (d.ext && !d.type.includes(d.ext) ? `（${esc(d.ext)}）` : "")],
          [it.dir ? "總大小" : "大小", `${fmtB(d.size)}${d.size >= 1024 ? `<span class="muted">（${d.size.toLocaleString()} 位元組）</span>` : ""}`]];
        if (d.dir) rows.push(["內容", `${d.files.toLocaleString()} 個檔案・${d.dirs.toLocaleString()} 個資料夾${d.partial ? "（太多了，只算了一部分）" : ""}`]);
        if (d.dims) rows.push(["照片尺寸", `${d.dims[0]} × ${d.dims[1]}（${(d.dims[0] * d.dims[1] / 1e6).toFixed(1)} 百萬像素）`]);
        rows.push([d.dir ? "建立時間" : "上傳時間", full(d.ctime)], ["修改時間", full(d.mtime)], ["位置", esc(this.niceDir(path.replace(/\/[^/]+$/, "")))]);
        if (it.kind === "video" || it.kind === "audio") rows.push(["長度", `<span data-dur>讀取中…</span>`]);
        if (it.kind === "video") rows.push(["畫面大小", `<span data-res>讀取中…</span>`]);
        body.querySelector(".drv-kv").innerHTML = rows.map(([k, v]) => `<div class="drv-kvrow"><span class="k">${k}</span><span class="v">${v}</span></div>`).join("");
        if (it.kind === "video" || it.kind === "audio") {
          const m = document.createElement(it.kind); m.preload = "metadata"; m.muted = true;
          m.onloadedmetadata = () => { const a = body.querySelector("[data-dur]"), r = body.querySelector("[data-res]");
            if (a) a.textContent = dur(m.duration); if (r) r.textContent = m.videoWidth ? `${m.videoWidth} × ${m.videoHeight}` : "—"; m.src = ""; };
          m.onerror = () => body.querySelectorAll("[data-dur],[data-res]").forEach(x => x.textContent = "—");
          m.src = this.fileUrl(it, true);
        }
      } catch (e) { body.querySelector(".drv-kv").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    }

    shareForm(it) {
      const { esc, icon } = this.o;
      const body = this.$(".drv-view-body");
      body.innerHTML = `<div class="drv-sheet drv-share">${this.o.badge("link", "#5e5ce6", "drv-ic")}
        <div class="t">分享「${esc(it.name)}」</div><div class="s">產生一個連結，拿到的人不用登入就能下載</div>
        <div class="drv-form">
          <div class="k">有效期限</div><div class="chipbtns" data-g="days">${[[1, "1 天"], [7, "7 天"], [30, "30 天"], [0, "永久"]].map(([v, l], i) => `<button class="chipbtn ${i === 1 ? "on" : ""}" data-v="${v}">${l}</button>`).join("")}</div>
          <div class="k">下載次數上限</div><div class="chipbtns" data-g="max">${[[0, "不限"], [1, "1 次"], [5, "5 次"], [20, "20 次"]].map(([v, l], i) => `<button class="chipbtn ${i === 0 ? "on" : ""}" data-v="${v}">${l}</button>`).join("")}</div>
          <div class="k">密碼（可以不設）</div><input type="text" class="drv-pw" placeholder="不設就不用密碼" autocomplete="off" autocapitalize="off">
        </div></div>`;
      body.onclick = e => { const b = e.target.closest(".chipbtn"); if (!b) return; b.parentElement.querySelectorAll(".chipbtn").forEach(x => x.classList.toggle("on", x === b)); };
      const box = this.$(".drv-view-btns");
      box.innerHTML = `<button class="btn primary" data-ok>${icon("link")}建立連結</button><button class="btn" data-m="close">取消</button>`;
      box.onclick = async e => {
        if (e.target.closest('[data-m="close"]')) return this.closeViewer();
        if (!e.target.closest("[data-ok]")) return;
        const pick = g => +body.querySelector(`[data-g="${g}"] .on`).dataset.v;
        try {
          const d = await this.post("share", { path: this.itemPath(it), days: pick("days"), max: pick("max"), password: body.querySelector(".drv-pw").value });
          body.onclick = null;
          body.innerHTML = `<div class="drv-sheet">${this.o.badge("link", "#30d158", "drv-ic")}<div class="t">連結建立好了</div>
            <div class="s" style="word-break:break-all;margin-top:6px">${esc(d.url)}</div></div>`;
          box.innerHTML = `<button class="btn primary" data-copy>${icon("clipboard")}複製連結</button><button class="btn" data-m="close">完成</button>`;
          box.onclick = async ev => {
            if (ev.target.closest('[data-m="close"]')) return this.closeViewer();
            if (ev.target.closest("[data-copy]")) { try { await navigator.clipboard.writeText(d.url); this.o.toast("已複製", "ok"); } catch { this.o.toast("請長按連結複製", "alert"); } }
          };
          try { await navigator.clipboard.writeText(d.url); this.o.toast("已建立並複製連結", "ok"); } catch {}
          if (this.o.onShared) this.o.onShared();
        } catch (err) { this.o.toast(err.message, "alert"); }
      };
    }

    refresh() { delete this.cache[this.path]; if (this.mode === "search") this.search(this.$(".drv-search input").value); else this.open(this.path); }

    async openTrash() {
      if (this.selecting) this.setSelecting(false);
      this.mode = "trash"; this.writable = false; this.toggleActions(); this.quota(null); this.crumbs("垃圾桶");
      const { esc, fmtB, icon } = this.o;
      try {
        const d = await this.req("trash", {});
        const rows = d.items.map(it => {
          const [ic, c] = KIND[it.kind] || KIND.file;
          return `<div class="drv-item">${this.o.badge(ic, c, "drv-ic")}<span class="drv-name"><span class="t">${esc(it.name)}</span>
            <span class="s">${esc(it.from)}・${it.dir ? "資料夾" : fmtB(it.size)}・${it.left_days} 天後永久刪除</span></span>
            ${it.writable ? `<button class="btn sm" data-tr="restore" data-id="${esc(it.id)}">還原</button>
            <button class="btn sm iconbtn danger" data-tr="purge" data-id="${esc(it.id)}" aria-label="永久刪除">${icon("x")}</button>` : ""}</div>`;
        }).join("");
        this.$(".drv-list").innerHTML = d.items.length ? `<div class="small muted" style="margin-bottom:6px">刪掉的檔案會在這裡保留 ${d.days} 天</div>${rows}
          <div style="text-align:center;margin-top:12px"><button class="btn sm danger" data-tr="empty">${icon("trash")}清空垃圾桶</button></div>`
          : `<div class="empty">垃圾桶是空的</div>`;
      } catch (e) { this.$(".drv-list").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    }

    async trashAction(op, id, btn) {
      if ((op === "purge" || op === "empty") && btn.dataset.confirm !== "1") {
        btn.dataset.confirm = "1"; btn.classList.remove("iconbtn"); btn.textContent = op === "empty" ? "確定全部永久刪除？" : "確定永久刪除？"; return;
      }
      try {
        if (op === "restore") { const d = await this.post("restore", { id }); this.o.toast("已還原到 " + d.restored_to, "ok"); this.cache = {}; }
        if (op === "purge") { await this.post("purge", { id }); this.o.toast("已永久刪除", "ok"); }
        if (op === "empty") { await this.post("empty_trash", {}); this.o.toast("垃圾桶已清空", "ok"); }
        this.openTrash();
      } catch (e) { this.o.toast(e.message, "alert"); }
    }

    async mkdir() {
      const box = this.$(".drv-view-btns");
      this.cur = null; this.$(".drv-view-body").onclick = null;
      this.$(".drv-view-body").innerHTML = `<div class="drv-sheet">${this.o.badge("folderplus", "#32ade6", "drv-ic")}<div class="t">新資料夾</div></div>`;
      box.innerHTML = `<input type="text" class="drv-input" placeholder="資料夾名稱"><button class="btn primary" data-ok>建立</button><button class="btn" data-m="close">取消</button>`;
      box.onclick = e => { if (e.target.closest('[data-m="close"]')) this.closeViewer(); };
      this.viewer.hidden = false;
      const inp = box.querySelector("input"); inp.focus();
      box.querySelector("[data-ok]").onclick = async () => {
        try { await this.post("mkdir", { path: this.path, name: inp.value.trim() }); this.closeViewer(); this.refresh(); }
        catch (err) { this.o.toast(err.message, "alert"); }
      };
    }

    async upload(files) {
      if (!files.length) return;
      const prog = this.$(".drv-prog"), bar = prog.querySelector("i"), txt = this.$(".drv-progtext");
      const all = files.reduce((a, f) => a + f.size, 0); let doneBytes = 0, ok = 0;
      const t0 = performance.now();
      prog.hidden = false;
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const res = await new Promise(resolve => {
          const x = new XMLHttpRequest();
          x.open("POST", this.o.url("upload", { path: this.path }));
          x.setRequestHeader("X-Filename", encodeURIComponent(f.name));
          Object.entries(this.o.headers || {}).forEach(([k, v]) => x.setRequestHeader(k, v));
          x.upload.onprogress = ev => {
            const sent = doneBytes + ev.loaded, sec = (performance.now() - t0) / 1000, rate = sent / Math.max(sec, .1);
            const left = rate > 0 ? Math.round((all - sent) / rate) : 0;
            bar.style.width = (sent / all * 100) + "%";
            txt.textContent = `${i + 1}/${files.length}・${f.name}・${this.o.fmtB(sent)} / ${this.o.fmtB(all)}・${this.o.fmtB(rate)}/秒${sec > 2 && left > 0 ? "・還要約 " + (left >= 60 ? Math.ceil(left / 60) + " 分鐘" : left + " 秒") : ""}`;
          };
          x.onload = () => { let d = {}; try { d = JSON.parse(x.responseText); } catch {} resolve(x.status < 300 && d.ok !== false ? null : (d.error || "HTTP " + x.status)); };
          x.onerror = () => resolve("連線中斷");
          x.send(f);
        });
        doneBytes += f.size;
        if (res) this.o.toast(f.name + "：" + res, "alert"); else ok++;
      }
      prog.hidden = true; bar.style.width = 0;
      if (ok) this.o.toast(`已上傳 ${ok} 個檔案`, "ok");
      this.refresh();
    }
  }
  window.DriveUI = DriveUI;
})();
