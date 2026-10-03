// Translates the pages as they are drawn. The UI is written in Traditional Chinese; the server puts the
// dictionary for the chosen language in front of this file (window.I18N_LANG / window.I18N_DICT, keyed by the
// Chinese source text, with {1} {2}… for interpolated parts). A MutationObserver translates every text node and
// a few attributes the moment they reach the page, so render code stays in Chinese and needs no t() calls.
(function () {
  const LANG = window.I18N_LANG || "zh-TW", DICT = window.I18N_DICT || {};
  const NAMES = { "zh-TW": "繁體中文", en: "English", "zh-CN": "简体中文", ja: "日本語", ko: "한국어", es: "Español" };
  const LOCALE = { "zh-TW": "zh-TW", en: "en-US", "zh-CN": "zh-CN", ja: "ja-JP", ko: "ko-KR", es: "es-ES" }[LANG] || "en-US";
  const HAN = /[㐀-鿿]/;
  const ATTRS = ["placeholder", "title", "aria-label", "alt"];
  const SKIP = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 1, PRE: 1, NOSCRIPT: 1 };

  // "{1} 天" -> regex. A blank at the very start/end is either empty (an icon was there) or set off by a real
  // space, so "{1} B/秒" can't eat the K of "4.5 KB/秒"; other spaces are optional.
  function compile(k, order) {
    const parts = k.split(/\{(\d+)\}/), esc = x => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/ /g, "\\s*");
    let rx = "";
    for (let i = 0; i < parts.length; i++) {
      if (!(i % 2)) continue;
      order.push(+parts[i]);
      const first = i === 1 && parts[0] === "", last = i === parts.length - 2 && parts[i + 1] === "";
      if (first && parts[i + 1].startsWith(" ")) { parts[i + 1] = parts[i + 1].slice(1); parts[i] = "(?:([\\s\\S]*?)\\s+)?"; }
      else if (last && parts[i - 1].endsWith(" ")) { parts[i - 1] = parts[i - 1].slice(0, -1); parts[i] = "(?:\\s+([\\s\\S]*?))?"; }
      else parts[i] = "([\\s\\S]*?)";
    }
    parts.forEach((p, i) => { rx += i % 2 ? p : esc(p); });
    return rx;
  }
  // templates with slots -> regexes; longer literal text first so the most specific one wins
  const PATTERNS = [];
  for (const k in DICT) {
    if (k.indexOf("{1}") < 0) continue;
    const order = [], src = compile(k, order);
    PATTERNS.push({ re: new RegExp("^" + src + "$"), order, to: DICT[k], weight: k.replace(/\{\d+\}/g, "").length });
  }
  PATTERNS.sort((a, b) => b.weight - a.weight);

  const memo = new Map();
  const WIDE = /^(zh|ja)/.test(LANG), SEP = WIDE ? "・" : " · ";
  // after translating into a language without full-width punctuation, tidy the leftovers (e.g. data like "SSH（22）")
  const narrow = s => WIDE ? s : s.replace(/\s*（/g, " (").replace(/）/g, ")").replace(/：\s*/g, ": ").replace(/，\s*/g, ", ").replace(/、\s*/g, ", ").replace(/^ /, "");
  // a template matches if every blank holds no Chinese, or Chinese that itself translates (strict); the loose pass
  // (names and other free text in a blank) only runs after the safer ways below have failed
  function viaPatterns(s, strict) {
    for (const p of PATTERNS) {
      const m = p.re.exec(s); if (!m) continue;
      const slot = {}; let ok = true;
      p.order.forEach((n, i) => { const v = m[i + 1] || "", tv = v.trim(); let tr = tv;
        if (HAN.test(tv)) { tr = core(tv); if (strict && tr === tv) ok = false; }
        slot[n] = tv ? v.replace(tv, tr) : v; });
      if (ok) return p.to.replace(/\{(\d+)\}/g, (x, n) => slot[n] === undefined ? x : slot[n]);
    }
  }
  function part(s) {  // one piece of a "A・B・C" line; many keys carry the leading dot themselves
    const out = core(s); if (out !== s) return out;
    const d = DICT["・" + s]; return d ? d.replace(/^\s*[・·]\s*/, "") : s;
  }
  function core(s) {
    if (!HAN.test(s)) return s;
    if (memo.has(s)) return memo.get(s);
    memo.set(s, s);  // guards against recursion through the steps below
    let out = DICT[s];
    if (out === undefined) out = viaPatterns(s, true);
    if (out === undefined && s.includes("・")) { const ps = s.split("・").map(x => x.trim()); const tr = ps.map(part); if (tr.some((x, i) => x !== ps[i])) out = tr.filter(Boolean).join(SEP); }
    if (out === undefined && s.includes("、")) { const ps = s.split("、").map(x => x.trim()); const tr = ps.map(core); if (tr.some((x, i) => x !== ps[i])) out = tr.join(/^(zh|ja)/.test(LANG) ? "、" : ", "); }
    if (out === undefined) { const m = /^([●○•#\d\s%.,:+\-]+)([\s\S]*[\u3400-\u9fff][\s\S]*)$/.exec(s); if (m) { const r = core(m[2]); if (r !== m[2]) out = m[1] + r; } }
    if (out === undefined) { const m = /^([\s\S]*[\u3400-\u9fff][\s\S]*?)\s*([（(][^\u3400-\u9fff（）()]*[）)])$/.exec(s); if (m) { const r = core(m[1]); if (r !== m[1]) out = r + (WIDE ? m[2] : " " + m[2].replace("（", "(").replace("）", ")")); } }
    if (out === undefined) out = viaPatterns(s, false);
    if (out === undefined || out === "") out = s; else out = narrow(out);
    if (memo.size > 5000) memo.clear();
    memo.set(s, out);
    return out;
  }
  // keep the surrounding whitespace, match on the collapsed text
  function t(s, vars) {
    if (s == null) return s;
    s = String(s);
    if (vars) {  // explicit use: t("已擋 {1} 筆", [n])
      const k = core(s);
      return k.replace(/\{(\d+)\}/g, (x, n) => vars[n - 1] ?? x);
    }
    if (LANG === "zh-TW" || !HAN.test(s)) return s;
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s), body = m[2].replace(/\s+/g, " ");
    const out = core(body);
    return out === body ? s : m[1] + out + m[3];
  }

  const mine = new WeakMap();  // node -> text we wrote, so our own writes aren't translated again
  function skip(el) { for (; el; el = el.parentElement) { if (SKIP[el.tagName] || el.getAttribute && el.getAttribute("translate") === "no") return true; } return false; }
  function textNode(n) {
    if (mine.get(n) === n.data || skip(n.parentElement)) return;
    if (!HAN.test(n.data)) {  // "56%・16.0 GB": the Japanese-style dot looks odd in other scripts
      if (!WIDE && n.data.includes("・")) { n.data = n.data.replace(/\s*・\s*/g, " · "); mine.set(n, n.data); }
      return;
    }
    const out = t(n.data);
    if (out !== n.data) { n.data = out; mine.set(n, out); }
  }
  function attrs(el) {
    for (const a of ATTRS) {
      const v = el.getAttribute(a); if (!v || !HAN.test(v)) continue;
      const out = t(v); if (out !== v) el.setAttribute(a, out);
    }
    if (el.tagName === "INPUT" && (el.type === "button" || el.type === "submit") && HAN.test(el.value)) el.value = t(el.value);
  }
  function walk(root) {
    if (root.nodeType === 3) return textNode(root);
    if (root.nodeType !== 1 || SKIP[root.tagName]) return;
    if (root.getAttribute("translate") === "no" || skip(root.parentElement)) return;
    attrs(root);
    const it = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: n => n.nodeType === 1 && (SKIP[n.tagName] || n.getAttribute("translate") === "no") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT });
    for (let n = it.nextNode(); n; n = it.nextNode()) n.nodeType === 3 ? textNode(n) : attrs(n);
  }

  function setLang(l) {
    try { localStorage.setItem("lang", l); } catch (e) {}
    document.cookie = "lang=" + encodeURIComponent(l) + "; Path=/; Max-Age=31536000; SameSite=Lax; Secure";
    location.reload();
  }
  // a <select> any page can drop in: <select data-langpick></select>
  function fillPickers(root) {
    (root.querySelectorAll ? root.querySelectorAll("select[data-langpick]") : []).forEach(sel => {
      if (sel.options.length) return;
      sel.setAttribute("translate", "no");
      for (const k in NAMES) sel.add(new Option(NAMES[k], k, false, k === LANG));
      sel.onchange = () => setLang(sel.value);
    });
  }

  // Monday-first weekday names; Chinese keeps the single characters the layout was designed around
  const weekdays = () => LANG === "zh-TW" ? [..."一二三四五六日"] : LANG === "zh-CN" ? [..."一二三四五六日"] :
    [...Array(7)].map((_, k) => new Date(2024, 0, 1 + k).toLocaleDateString(LOCALE, { weekday: "short" }));
  window.I18N = { lang: LANG, locale: LOCALE, names: NAMES, t, set: setLang, apply: walk, weekdays };
  window.t = t;
  document.documentElement.lang = { "zh-TW": "zh-Hant", "zh-CN": "zh-Hans" }[LANG] || LANG;
  if (LANG !== "zh-TW") {
    new MutationObserver(list => {
      for (const m of list) {
        if (m.type === "characterData") textNode(m.target);
        else if (m.type === "attributes") attrs(m.target);
        else for (const n of m.addedNodes) walk(n);
      }
    }).observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS.concat(["value"]) });
  }
  const ready = () => { if (LANG !== "zh-TW") walk(document.documentElement); fillPickers(document); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready); else ready();
  new MutationObserver(l => l.forEach(m => m.addedNodes.forEach(n => {
    if (n.nodeType === 1 && (n.matches("select[data-langpick]") || n.querySelector("select[data-langpick]"))) fillPickers(n.parentElement || n);
  }))).observe(document.documentElement, { childList: true, subtree: true });

  // debugging aid: I18N.missing() lists Chinese text still on screen
  window.I18N.missing = () => {
    const out = new Set(), it = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    // languages written with Chinese characters: only text that is still a source string counts
    const left = v => HAN.test(v) && (!/^(zh|ja)/.test(LANG) || (mine.get(v) === undefined && ![undefined, v.trim().replace(/\s+/g, " ")].includes(DICT[v.trim().replace(/\s+/g, " ")])));
    for (let n = it.nextNode(); n; n = it.nextNode()) if (mine.get(n) !== n.data && left(n.data) && !skip(n.parentElement) && n.parentElement.offsetParent !== null) out.add(n.data.trim());
    document.querySelectorAll("[placeholder],[title],[aria-label],[alt]").forEach(e => ATTRS.forEach(a => { const v = e.getAttribute(a); if (v && left(v) && !skip(e)) out.add("@" + a + ": " + v); }));
    return [...out];
  };
})();
