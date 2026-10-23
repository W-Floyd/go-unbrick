// The browse page: one Alpine component over api/info, api/level, api/preview and
// api/raw, on what it shares with the diff page (shared.js).
function browse() {
  const u = window.unbrick;
  return {
    ...u.nav({
      watch: ['match', 'grep'],
      writeExtra: (c, u) => {
        if (c.match) u.set('match', c.match);
        if (c.grep) u.set('grep', c.grep);
      },
      readExtra: (c, u) => {
        c.match = u.get('match') || '';
        c.grep = u.get('grep') || '';
      },
      keys: (ev, c) => {
        switch (ev.key) {
          case 'w': c.wrap = !c.wrap; return true;
          case 'p': c.pretty = !c.pretty; c.reload(); return true;
        }
        return false;
      },
      onMove: (c) => { c.cur = null; },
      onRestore: (c) => { c.cur = null; },
    }),
    match: '',
    grep: '',
    filtering: false,
    filterError: '',
    _filterTimer: null,
    info: { title: '', recon: false },
    cur: null,
    pretty: true,
    wrap: u.store.get('browse-wrap', true),
    loading: false,
    error: '',
    note: '',
    _seq: 0,

    async init() {
      this.$watch('wrap', (v) => u.store.set('browse-wrap', v));
      this.startUrl();
      u.watchProgress(this);
      try { this.info = await u.get('api/info'); document.title = this.info.title || 'Browse'; } catch (e) { this.error = String(e.message || e); }
      await this.loadLevel();
    },

    async loadLevel() {
      this.loading = true; this.error = '';
      try {
        this.entries = (await u.get('api/level?' + u.q(this.levelQuery()))).entries;
      } catch (e) {
        // A place that is not there is the top.
        if (this.path.length) { this.path = []; this.sel = ''; return this.loadLevel(); }
        this.error = String(e.message || e);
        this.entries = [];
      } finally { this.loading = false; }
      if (!this.entries.some((e) => e.name === this.sel)) this.sel = this.entries.length ? this.entries[0].name : '';
      await this.reload();
    },

    // reload asks for the preview of the entry on screen. The report that recon is
    // still making is asked for again until it lands.
    async reload(again) {
      const e = this.entries.find((e) => e.name === this.sel);
      if (!e) { this.cur = null; return; }
      const seq = again ?? ++this._seq;
      if (again === undefined && this.cur && this.cur.entry.name !== e.name) this.cur = null;
      this.loading = true; this.note = '';
      try {
        const r = await u.get('api/preview?' + u.q([...this.levelQuery(), ['name', e.name], ...(this.pretty ? [] : [['raw', '1']])]));
        if (seq !== this._seq) return;
        this.cur = r;
        if (r.recon && r.recon.state === 'running') setTimeout(() => { if (seq === this._seq) this.reload(seq); }, 800);
      } catch (err) {
        if (seq === this._seq) this.cur = { entry: e, kind: 'binary', err: String(err.message || err) };
      } finally { if (seq === this._seq) this.loading = false; }
    },

    async fullDownload() {
      if (!this.cur) return;
      try {
        const r = await fetch('api/fulldownload?' + u.q([...this.levelQuery(), ['name', this.cur.entry.name]]), { method: 'POST' });
        if (!r.ok) throw new Error((await r.text()).trim());
      } catch (e) { this.note = String(e.message || e); return; }
      await this.reload();
    },

    select(e) { this.sel = e.name; return this.reload(); },
    async open(e) {
      if (!e.openable && !e.dir) return;
      // Opening may turn out to be nothing (a file on disk that carve does not open).
      try { await u.get('api/level?' + u.q([...this.levelQuery(), ['p', e.name]])); } catch (err) { this.note = String(err.message || err); return; }
      await this.enter(e.name);
    },

    rawUrl(download) {
      if (!this.cur) return '#';
      return 'api/raw?' + u.q([...this.levelQuery(), ['name', this.cur.entry.name], ...(download ? [['download', '1']] : [])]);
    },
    preview() { return this.cur ? u.previewHTML(this.cur, (d) => this.rawUrl(d)) : ''; },

    // ---- formatting ----
    // levelQuery override: --match/--grep ride on every api/level, api/preview and
    // api/raw request, same as the path, so the server applies them to whichever
    // level is being asked for (see browseServer.applyFilters).
    levelQuery() {
      const q = this.path.map((p) => ['p', p]);
      if (this.match) q.push(['match', this.match]);
      if (this.grep) q.push(['grep', this.grep]);
      return q;
    },
    // filterChanged debounces typing in either box, then reloads under the new
    // filters; a bad regex comes back as an error from the server, shown by the
    // inputs rather than in the page's general error line.
    filterChanged() {
      clearTimeout(this._filterTimer);
      this._filterTimer = setTimeout(async () => {
        this.filtering = true;
        await this.loadLevel();
        if (this.error) { this.filterError = this.error; this.error = ''; }
        else { this.filterError = ''; }
        this.filtering = false;
      }, 350);
    },

    trim: u.trim,
    size: u.size,
    kind(e) { return e.dir ? 'dir' : e.container ? 'container' : e.image ? 'image' : e.text ? 'text' : 'file'; },
    glyph(e) { return e.dir ? '/' : e.container ? '▸' : e.image ? '▣' : e.text ? '¶' : '·'; },
  };
}
