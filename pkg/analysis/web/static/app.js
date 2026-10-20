// The diff page: one Alpine component over the JSON API (api/state, api/level,
// api/entry, api/deepen): the same calls the terminal viewer makes of the analysis
// package. Moving through levels and keeping the place in the URL is shared.js's.
function app() {
  const u = window.unbrick;
  const GLYPH = { changed: '~', renamed: '>', 'renamed-changed': '≈', added: '+', removed: '-', unchanged: '=', dir: '/', note: '', 'metadata-only': '≡' };
  const views = ['auto', 'strings', 'overlap', 'hex'];
  return {
    ...u.nav({
      // The place is the level, the entry, the view and whether words are marked.
      watch: ['view', 'words'],
      writeExtra: (c, p) => {
        if (c.view !== 'auto') p.set('view', c.view);
        if (!c.words) p.set('words', '0');
      },
      readExtra: (c, p) => {
        c._wantSel = !!c.sel; // kept while the comparison has not found it yet
        c.view = views.includes(p.get('view')) ? p.get('view') : 'auto';
        if (p.get('words') === '0') c.words = false;
      },
      onMove: (c) => { c.cur = null; c._curSig = ''; },
      onRestore: (c) => { c.cur = null; c._curSig = ''; c.loadInfo = null; },
      keys: (ev, c) => {
        switch (ev.key) {
          case '1': case '2': case '3': case '4': c.setView(views[+ev.key - 1]); return true;
          case 'w': c.wrap = !c.wrap; return true;
          case 'D': c.deeper(); return true;
          case 'd': c.words = !c.words; c.reload(); return true;
          case 'x': c.hexMore = !c.hexMore; c.setView('hex'); return true;
        }
        return false;
      },
    }),
    views,
    state: { title: '', finished: false, summary: '', status: '', err: '' },
    level: { title: '', busy: false },
    cur: null,
    view: 'auto',
    wrap: u.store.get('wrap', true),
    words: u.store.get('words', true),
    hexMore: false,
    loading: false,
    deepenNote: '',
    loadInfo: null, // how far the read of the entry on screen has got: {read, total}
    _seq: 0,
    _curSig: '',
    _timer: null,

    async init() {
      this.$watch('wrap', (v) => u.store.set('wrap', v));
      this.$watch('words', (v) => u.store.set('words', v));
      // A link opens the same level, entry and view, and back/forward move through levels.
      this.startUrl();
      await this.poll();
      this._timer = setInterval(() => this.poll(), 700);
    },

    // poll refreshes what may have changed while the comparison runs.
    async poll() {
      try {
        this.state = await u.get('api/state');
        document.title = (this.state.title || 'Diff') + (this.state.finished ? '' : ' …');
        await this.loadLevel();
      } catch (e) {
        // The server is gone, or the level is not there: while the comparison runs it
        // may yet be found; once finished, a place that does not exist is the top.
        if (this.state.finished && this.path.length) { this.path = []; this.sel = ''; this._wantSel = false; this._curSig = ''; this.cur = null; }
      }
    },

    async loadLevel() {
      const lv = await u.get('api/level?' + u.q(this.levelQuery()));
      this.level = { title: lv.title, busy: lv.busy };
      this.entries = lv.entries;
      if (!this.entries.some((e) => e.name === this.sel)) {
        // A selection from the URL waits for the comparison to find it.
        if (this._wantSel && this.sel && !this.state.finished) { this.cur = null; return; }
        this.sel = this.entries.length ? this.entries[0].name : '';
      }
      this._wantSel = false;
      const e = this.entries.find((e) => e.name === this.sel);
      // The entry on screen is read again only when it has become something else.
      const sig = e ? [e.kind, e.pending, e.hasKids, e.summary, e.sizeNote].join('|') : '';
      if (e && (sig !== this._curSig || !this.cur)) { this._curSig = sig; await this.reload(); }
      if (!e) { this.cur = null; this._curSig = ''; }
    },

    // reload asks for the entry on screen. A file is read in the background, so the
    // answer may be "still reading, this far": the page asks again (again = the same
    // request, not a new one).
    async reload(again) {
      const e = this.entries.find((e) => e.name === this.sel);
      if (!e) return;
      const seq = again ?? ++this._seq;
      if (again === undefined && this.cur && this.cur.entry.name !== e.name) this.cur = null; // not the old entry's pane under the new one
      if (again === undefined) this.loadInfo = null;
      this.loading = true;
      try {
        const r = await u.get('api/entry?' + u.q([...this.levelQuery(), ['name', e.name], ['view', this.view],
          ['words', this.words ? '1' : '0'], ['more', this.hexMore ? '1' : '0']]));
        if (seq !== this._seq) return; // a slower answer for an entry the cursor left is dropped
        if (r.loading) {
          this.loadInfo = r.loading;
          setTimeout(() => { if (seq === this._seq) this.reload(seq); }, 350);
          return;
        }
        this.loadInfo = null;
        this.cur = r;
        this.loading = false;
      } catch (err) {
        if (seq !== this._seq) return;
        this.loadInfo = null;
        this.loading = false;
        this.cur = { entry: e, title: e.kind, detail: { err: String(err.message || err) } };
      }
    },

    progress() {
      const l = this.loadInfo;
      return l && l.total > 0 ? Math.min(100, Math.round(100 * l.read / l.total)) : 0;
    },
    // canOpen says whether there is somewhere to go in: a directory, a container
    // with differences inside, or the container on screen (its members can be listed).
    canOpen(e) {
      return e.kind === 'dir' || e.hasKids || (!!this.cur && !!this.cur.container && this.cur.entry.name === e.name);
    },
    select(e) { this.sel = e.name; this._curSig = ''; return this.loadLevel(); },
    async open(e) {
      if (e.kind === 'note' || !this.canOpen(e)) return;
      await this.enter(e.name);
    },
    setView(v) { this.view = v; return this.reload(); },

    // deeper compares one more container level: the pairs the first pass stopped at
    // have their members compared now, and appear in the list as they are found.
    async deeper() {
      this.deepenNote = '';
      try {
        const r = await fetch('api/deepen', { method: 'POST' });
        if (!r.ok) throw new Error(await r.text());
        const d = await r.json();
        this.deepenNote = d.started ? 'comparing ' + d.started + ' more…' : 'nothing left to compare deeper';
        await this.poll();
      } catch (e) {
        this.deepenNote = String(e.message || e).trim();
      }
    },

    // A file on one side only is previewed as browse previews any file.
    rawUrl(download) {
      if (!this.cur) return '#';
      return 'api/raw?' + u.q([...this.levelQuery(), ['name', this.cur.entry.name], ...(download ? [['download', '1']] : [])]);
    },
    previewHTML() { return this.cur && this.cur.preview ? u.previewHTML(this.cur.preview, (d) => this.rawUrl(d)) : ''; },

    // ---- formatting ----
    rootTitle() { return this.state.title || 'top'; },
    trim: u.trim,
    size: u.size,
    count: u.count,
    pct: u.pct,
    glyph(k) { return GLYPH[k] ?? ''; },
    bytesN(n) { return this.count(n) + (n === 1 ? ' differs' : ' differ'); },
    opName(op) { return { '+': 'add', '-': 'del', '@': 'hunk', ' ': 'ctx' }[op] || 'ctx'; },
    segs(l) { return l.segs || [{ t: l.text }]; },
    partial(d) {
      const p = [];
      if (d.a && d.a.truncated) p.push('A: first ' + this.size(d.a.read) + ' of ' + this.size(d.a.size));
      if (d.b && d.b.truncated) p.push('B: first ' + this.size(d.b.read) + ' of ' + this.size(d.b.size));
      return p.length ? 'only part was read (' + p.join('; ') + ')' : '';
    },
    headerSummary(r) {
      const f = Object.entries(r.byField || {}).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
      return f.length ? 'Differs: ' + f.map(([k, n]) => k + ' of ' + n + ' of ' + r.members + ' members').join('; ') : '';
    },
    verdict(b) {
      const v = b.verdict; if (!v) return { cls: '', text: '' };
      const part = (this.cur.detail.a.truncated || this.cur.detail.b.truncated) ? ' (in the part read)' : '';
      if (v.only) return { cls: 'add', text: 'Only strings differ' + part + ': the ' + this.size(v.residueA) + ' outside printable strings are identical' };
      if (v.residueDiffering > 0) return { cls: 'mid', text: 'Not only strings' + part + ': ' + this.count(v.residueDiffering) + ' of the ' + this.size(v.residueA) + ' outside printable strings ' + (v.residueDiffering === 1 ? 'differs' : 'differ') + ' too' };
      if (v.residueDiffering < 0) return { cls: 'mid', text: 'Not only strings' + part + ': what is outside them differs in size too (A ' + this.size(v.residueA) + ', B ' + this.size(v.residueB) + ')' };
      return { cls: '', text: '' };
    },
    overlapHow(o) {
      return o.chunk > 0 ? '(content-defined chunks, about ' + this.size(o.chunk) + ': an insertion does not shift what follows; a changed byte makes its whole chunk unique)'
        : '(measured byte for byte: the stretches the two have in common, in order)';
    },
    cell(f) {
      const h = f <= 0 ? 12 : Math.round(12 + f * 88);
      const c = f >= 0.9 ? 'var(--add)' : f >= 0.5 ? 'var(--mid)' : 'var(--del)';
      return 'height:' + h + '%;background:' + c;
    },
    // hexRows lays a window of bytes out in rows of 16 (8 when the pane is narrow), the hunk's bytes marked.
    hexRows(w) {
      if (!w.hex) return [];
      const per = window.innerWidth < 900 ? 8 : 16;
      const bytes = w.hex.match(/../g).map((h) => parseInt(h, 16));
      const rows = [];
      for (let r = 0; r < bytes.length; r += per) {
        const cells = []; let asc = '';
        for (let i = r; i < r + per; i++) {
          if (i >= bytes.length) { cells.push({ h: '  ', hit: false }); continue; }
          const b = bytes[i];
          cells.push({ h: b.toString(16).padStart(2, '0'), hit: i >= w.from && i < w.to });
          asc += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
        }
        rows.push({ off: (w.offset + r).toString(16).padStart(8, '0'), cells, asc });
      }
      return rows;
    },
  };
}
