// What the diff page and the browse page have in common: formatting, fetching, and
// moving through levels with the place kept in the URL fragment, in the text form
// of the Go library's analysis.Location (p=<level>&p=...&sel=<entry>&...).
window.unbrick = (() => {
  const q = (params) => params.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');

  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private window */ } },
  };

  const size = (n) => {
    if (n < 1024) return n + ' B';
    const u = 'KMGT'; let e = 0; let d = 1024;
    while (n / d >= 1024 && e < 3) { d *= 1024; e++; }
    return (n / d).toFixed(1) + ' ' + u[e] + 'iB';
  };

  const get = async (url) => {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error((await r.text()).trim());
    return r.json();
  };

  const escapeHTML = (s) => (s || '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

  // nav is the part of a page's Alpine component that goes in and out of levels and
  // keeps the place in the URL. The page supplies, in cfg:
  //   watch:      the component's own fields that are part of the place (['view', 'words'])
  //   writeExtra: (component, URLSearchParams) adds them to the fragment
  //   readExtra:  (component, URLSearchParams) takes them back
  //   loadLevel:  () lists the current level and shows the selection
  //   canOpen:    (entry) whether Enter goes in
  //   keys:       (event, component) -> true when the page handled the key itself
  //   isDir:      (entry) whether tapping it on a phone goes into it (default: entry.dir)
  const nav = (cfg) => ({
    path: [],
    sel: '',
    entries: [],
    detail: false, // on a phone, the entry is shown instead of the list
    _urlPath: '',

    levelQuery() { return this.path.map((p) => ['p', p]); },

    fragment() {
      const u = new URLSearchParams();
      for (const p of this.path) u.append('p', p);
      if (this.sel) u.set('sel', this.sel);
      if (cfg.writeExtra) cfg.writeExtra(this, u);
      return u.toString();
    },
    fromFragment(h) {
      const u = new URLSearchParams(h.replace(/^[#?]/, ''));
      this.path = u.getAll('p');
      this.sel = u.get('sel') || '';
      if (cfg.readExtra) cfg.readExtra(this, u);
    },
    toFragment() {
      const f = this.fragment();
      const h = f ? '#' + f : '';
      if (h === location.hash || (!h && !location.hash)) return;
      const here = this.path.join('\0');
      // A new level is a step Back can return to; a selection or a view is not.
      history[here !== this._urlPath ? 'pushState' : 'replaceState'](null, '', location.pathname + location.search + h);
      this._urlPath = here;
    },
    // startUrl reads the place from the URL and from then on keeps the URL in step.
    startUrl() {
      this.fromFragment(location.hash);
      this._urlPath = this.path.join('\0');
      for (const k of ['path', 'sel', ...(cfg.watch || [])]) this.$watch(k, () => this.toFragment());
      window.addEventListener('popstate', () => {
        if (this.detail) { this.detail = false; return; } // Back from an entry to the list
        this.restore();
      });
    },
    async restore() {
      this.fromFragment(location.hash);
      this._urlPath = this.path.join('\0');
      if (cfg.onRestore) cfg.onRestore(this);
      try { await this.loadLevel(); } catch (e) { /* not there (yet) */ }
    },

    async up() {
      this.detail = false;
      if (!this.path.length) return;
      const from = this.path[this.path.length - 1];
      this.path = this.path.slice(0, -1);
      this.sel = from;
      if (cfg.onMove) cfg.onMove(this);
      await this.loadLevel();
    },
    async goTo(n) { while (this.path.length > n) await this.up(); },
    // enter goes into a level: the page decides first whether there is one.
    async enter(name) {
      this.detail = false;
      this.path = [...this.path, name];
      this.sel = ''; this.entries = [];
      if (cfg.onMove) cfg.onMove(this);
      await this.loadLevel();
    },

    // narrow says the window is a phone's: one pane at a time, the list or the entry.
    narrow() { return window.matchMedia('(max-width: 760px)').matches; },
    // tap is a touch on a row: it selects it, and on a phone goes into a directory or shows the entry.
    async tap(e) {
      await this.select(e);
      if (!this.narrow()) return;
      if (cfg.isDir ? cfg.isDir(e) : e.dir) { await this.open(e); return; }
      this.detail = true;
      history.pushState({ detail: true }, '', location.href);
      this.$nextTick(() => document.querySelector('.detail')?.scrollTo(0, 0));
    },
    // hideDetail goes back from the entry to the list, as Back does.
    hideDetail() {
      if (history.state && history.state.detail) history.back();
      else this.detail = false;
    },

    key(ev) {
      if (ev.target.closest('input,textarea') || ev.ctrlKey || ev.metaKey || ev.altKey) return;
      const i = this.entries.findIndex((e) => e.name === this.sel);
      const move = (d) => {
        const e = this.entries[Math.max(0, Math.min(this.entries.length - 1, i + d))];
        if (e) { this.select(e); this.$nextTick(() => document.querySelector('.row.sel')?.scrollIntoView({ block: 'nearest' })); }
      };
      switch (ev.key) {
        case 'j': case 'ArrowDown': move(1); break;
        case 'k': case 'ArrowUp': move(-1); break;
        case 'Enter': case 'l': case 'ArrowRight': if (this.entries[i]) this.open(this.entries[i]); break;
        case 'h': case 'ArrowLeft': case 'Backspace': if (this.detail) this.hideDetail(); else this.up(); break;
        default:
          if (!cfg.keys || !cfg.keys(ev, this)) return;
      }
      ev.preventDefault();
    },
  });

  const attr = (s) => escapeHTML(s).replace(/"/g, '&quot;');

  const bars = (vals, max, title) => '<svg class="entropy-bars" viewBox="0 0 ' + vals.length + ' 32" preserveAspectRatio="none" role="img" aria-label="' + attr(title) + '">' +
    vals.map((v, i) => { const h = Math.max(0.5, 32 * v / max); return '<rect x="' + i + '" y="' + (32 - h) + '" width="0.85" height="' + h + '"><title>' + attr(title) + ' ' + i + ': ' + (+v.toFixed(3)) + '</title></rect>'; }).join('') + '</svg>';

  // entropyHTML rates how random a binary looks: entropy along the file, and the
  // byte-value histogram (flat for ciphertext).
  const entropyHTML = (p) => {
    const e = p.entropy;
    if (!e) return '';
    const hist = p.byteHist || [];
    const hmax = Math.max(1, ...hist);
    return '<div class="entropy"><p class="dim">entropy ' + e.bits.toFixed(4) + ' bits/byte: ' + escapeHTML(e.class) + '</p>' +
      '<p class="dim">entropy per ' + Math.round(e.block / 1024) + ' KiB block (full height = 8 bits)</p>' + bars(e.blocks, 8, 'block') +
      (hist.length ? '<p class="dim">byte values (bins of 4)</p>' + bars(hist, hmax, 'bin') : '') + '</div>';
  };

  // previewHTML is how both pages show one file on its own: its text, highlighted by
  // the server (already escaped), or an image fetched from the raw route.
  const previewHTML = (p, rawUrl) => {
    if (p.kind === 'image') return `<img class="preview-img" src="${attr(rawUrl(false))}" alt="${attr(p.entry.name)}" loading="lazy">`;
    if (p.kind === 'binary') {
      return entropyHTML(p) + (p.strings && p.strings.length
        ? '<p class="dim">binary; the printable strings in its start:</p><pre class="text">' + p.strings.map(escapeHTML).join('\n') + '</pre>'
        : '');
    }
    if (p.kind !== 'text') return '';
    return `<pre class="chroma text">${p.html || escapeHTML(p.text)}</pre>` +
      (p.truncated ? '<p class="mid">preview truncated; download for the whole file</p>' : '');
  };

  // progressLine is the newest running task as "unpacking x 45% · 12s left".
  const progressLine = (tasks) => {
    const t = tasks && tasks[tasks.length - 1];
    if (!t) return '';
    let s = t.label;
    if (t.percent >= 0) s += ' ' + t.percent + '%';
    if (t.eta >= 0) s += ' · ' + (t.eta >= 90 ? Math.round(t.eta / 60) + 'm' : Math.round(t.eta) + 's') + ' left';
    return s;
  };

  // watchProgress keeps c.progText current while c.loading, so a wait that has no
  // byte count of its own (listing an archive, unpacking it) still says how far.
  const watchProgress = (c) => {
    c.progText = '';
    setInterval(async () => {
      if (!c.loading) { c.progText = ''; return; }
      try { c.progText = progressLine(await get('api/progress')); } catch { /* the next tick asks again */ }
    }, 600);
  };

  return {
    q, store, size, get, escapeHTML, previewHTML, nav, progressLine, watchProgress,
    trim: (n) => n.replace(/\/$/, ''),
    count: (n) => n + (n === 1 ? ' byte' : ' bytes'),
    pct: (part, whole) => (whole ? Math.round(100 * part / whole) + '%' : '—'),
  };
})();
