// The page is one Alpine component over the JSON API (api/state, api/level,
// api/entry): the same calls the terminal viewer makes of the analysis package.
function app() {
  const GLYPH = { changed: '~', renamed: '>', 'renamed-changed': '≈', added: '+', removed: '-', unchanged: '=', dir: '/', note: '' };
  const q = (params) => params.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  };
  return {
    views: ['auto', 'strings', 'overlap', 'hex'],
    state: { title: '', finished: false, summary: '', status: '', err: '' },
    path: [],
    entries: [],
    level: { title: '', busy: false },
    sel: '',
    cur: null,
    view: 'auto',
    wrap: store.get('wrap', true),
    words: store.get('words', true),
    hexMore: false,
    loading: false,
    _seq: 0,
    _curSig: '',
    _timer: null,

    async init() {
      this.$watch('wrap', (v) => store.set('wrap', v));
      this.$watch('words', (v) => store.set('words', v));
      await this.poll();
      this._timer = setInterval(() => this.poll(), 700);
    },

    async get(url) {
      const r = await fetch(url, { cache: 'no-store' });
      if (!r.ok) throw new Error(await r.text());
      return r.json();
    },

    // poll refreshes what may have changed while the comparison runs.
    async poll() {
      try {
        this.state = await this.get('api/state');
        document.title = (this.state.title || 'Diff') + (this.state.finished ? '' : ' …');
        await this.loadLevel();
      } catch (e) { /* the server is gone, or the level no longer exists: keep what is shown */ }
    },

    async loadLevel() {
      const lv = await this.get('api/level?' + q(this.path.map((p) => ['p', p])));
      this.level = { title: lv.title, busy: lv.busy };
      this.entries = lv.entries;
      if (!this.sel || !this.entries.some((e) => e.name === this.sel)) {
        this.sel = this.entries.length ? this.entries[0].name : '';
      }
      const e = this.entries.find((e) => e.name === this.sel);
      // The entry on screen is read again only when it has become something else.
      const sig = e ? [e.kind, e.pending, e.hasKids, e.summary, e.sizeNote].join('|') : '';
      if (e && (sig !== this._curSig || !this.cur)) { this._curSig = sig; await this.reload(); }
      if (!e) { this.cur = null; this._curSig = ''; }
    },

    async reload() {
      const e = this.entries.find((e) => e.name === this.sel);
      if (!e) return;
      const seq = ++this._seq;
      this.loading = true;
      try {
        const r = await this.get('api/entry?' + q([...this.path.map((p) => ['p', p]), ['name', e.name], ['view', this.view],
          ['words', this.words ? '1' : '0'], ['more', this.hexMore ? '1' : '0']]));
        if (seq === this._seq) this.cur = r; // a slower answer for an entry the cursor left is dropped
      } catch (err) {
        if (seq === this._seq) this.cur = { entry: e, title: e.kind, detail: { err: String(err.message || err) } };
      } finally {
        if (seq === this._seq) this.loading = false;
      }
    },

    // canOpen says whether there is somewhere to go in: a directory, a container
    // with differences inside, or the container on screen (its members can be listed).
    canOpen(e) {
      return e.kind === 'dir' || e.hasKids || (!!this.cur && !!this.cur.container && this.cur.entry.name === e.name);
    },
    select(e) { this.sel = e.name; this._curSig = ''; return this.loadLevel(); },
    async open(e) {
      if (e.kind === 'note' || (!e.hasKids && e.kind !== 'dir' && !(this.cur && this.cur.container && this.cur.entry.name === e.name))) return;
      this.path = [...this.path, e.name];
      this.sel = ''; this.cur = null; this._curSig = ''; this.entries = [];
      await this.loadLevel();
    },
    async up() {
      if (!this.path.length) return;
      const from = this.path[this.path.length - 1];
      this.path = this.path.slice(0, -1);
      this.sel = from; this.cur = null; this._curSig = '';
      await this.loadLevel();
    },
    async goTo(n) { while (this.path.length > n) await this.up(); },
    setView(v) { this.view = v; return this.reload(); },

    key(ev) {
      if (ev.target.closest('input,textarea') || ev.ctrlKey || ev.metaKey || ev.altKey) return;
      const i = this.entries.findIndex((e) => e.name === this.sel);
      const move = (d) => { const e = this.entries[Math.max(0, Math.min(this.entries.length - 1, i + d))]; if (e) { this.select(e); this.$nextTick(() => document.querySelector('.row.sel')?.scrollIntoView({ block: 'nearest' })); } };
      switch (ev.key) {
        case 'j': case 'ArrowDown': move(1); break;
        case 'k': case 'ArrowUp': move(-1); break;
        case 'Enter': case 'l': case 'ArrowRight': if (this.entries[i]) this.open(this.entries[i]); break;
        case 'h': case 'ArrowLeft': case 'Backspace': this.up(); break;
        case '1': case '2': case '3': case '4': this.setView(this.views[+ev.key - 1]); break;
        case 'w': this.wrap = !this.wrap; break;
        case 'd': this.words = !this.words; this.reload(); break;
        case 'x': this.hexMore = !this.hexMore; this.setView('hex'); break;
        default: return;
      }
      ev.preventDefault();
    },

    // ---- formatting ----
    rootTitle() { return this.state.title || 'top'; },
    trim(n) { return n.replace(/\/$/, ''); },
    glyph(k) { return GLYPH[k] ?? ''; },
    size(n) {
      if (n < 1024) return n + ' B';
      const u = 'KMGT'; let e = 0; let d = 1024;
      while (n / d >= 1024 && e < 3) { d *= 1024; e++; }
      return (n / d).toFixed(1) + ' ' + u[e] + 'iB';
    },
    count(n) { return n + (n === 1 ? ' byte' : ' bytes'); },
    bytesN(n) { return this.count(n) + (n === 1 ? ' differs' : ' differ'); },
    pct(part, whole) { return whole ? Math.round(100 * part / whole) + '%' : '—'; },
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
