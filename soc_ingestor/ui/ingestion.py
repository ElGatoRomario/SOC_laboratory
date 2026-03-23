"""Ingestion UI — Bulk and Stream tabs."""

import tkinter as tk
from tkinter import ttk, messagebox
import random, time, threading, json

from ..config import LOG_CATEGORIES, get_index, is_data_stream
from ..generators import GENERATORS
from ..generators.helpers import now_timestamp
from ..clients.elastic import ensure_data_stream, prepare_for_data_stream

try:
    from elasticsearch import helpers
except ImportError:
    helpers = None


class IngestionPanel:
    """Builds Bulk + Stream sub-tabs inside a parent notebook."""

    def __init__(self, parent_nb, cfg, es, log_fn):
        self.cfg = cfg
        self.es = es
        self.log = log_fn
        self.running = False
        self._stop = threading.Event()
        self._build(parent_nb)

    def _cat_labels(self):
        cl = {}
        for cat, m in LOG_CATEGORIES.items():
            tag = " [DS]" if is_data_stream(self.cfg, cat) else ""
            cl[cat] = f"{m['label']} → {get_index(self.cfg, cat)}{tag}"
        return cl

    def _build(self, nb):
        cl = self._cat_labels()

        # ── Bulk tab ─────────────────────────────────────────
        bf = ttk.Frame(nb, padding=10); nb.add(bf, text="  📦 Bulk  ")
        lf = ttk.LabelFrame(bf, text="  Tipos  ", padding=8); lf.pack(fill="x", pady=(0, 6))
        self.log_vars = {}; self.log_counts = {}
        rf = ttk.Frame(lf); rf.pack(fill="x")
        for i, (cat, lbl) in enumerate(cl.items()):
            cf = ttk.Frame(rf); cf.grid(row=i // 2, column=i % 2, sticky="w", padx=8, pady=3)
            v = tk.BooleanVar(value=True); self.log_vars[cat] = v
            ttk.Checkbutton(cf, text=lbl, variable=v).pack(side="left")
            sp = tk.Spinbox(cf, from_=1, to=100000, width=7,
                            bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                            buttonbackground="#45475a", relief="flat", font=("Segoe UI", 10))
            sp.delete(0, "end"); sp.insert(0, "500")
            sp.pack(side="left", padx=(5, 0)); self.log_counts[cat] = sp
        bbf = ttk.Frame(bf); bbf.pack(pady=6)
        self.bulk_btn = ttk.Button(bbf, text="▶ Bulk", style="Accent.TButton", command=self._start_bulk)
        self.bulk_btn.pack()
        self.bulk_prog = ttk.Progressbar(bf, mode="determinate", length=380)
        self.bulk_prog.pack(pady=4)

        # ── Stream tab ───────────────────────────────────────
        sf = ttk.Frame(nb, padding=10); nb.add(sf, text="  🌊 Stream  ")
        s1 = ttk.LabelFrame(sf, text="  Tipos  ", padding=8); s1.pack(fill="x", pady=(0, 6))
        self.stream_vars = {}; sr = ttk.Frame(s1); sr.pack(fill="x")
        for i, (cat, lbl) in enumerate(cl.items()):
            cf = ttk.Frame(sr); cf.grid(row=i // 2, column=i % 2, sticky="w", padx=8, pady=3)
            v = tk.BooleanVar(value=True); self.stream_vars[cat] = v
            ttk.Checkbutton(cf, text=lbl, variable=v).pack(side="left")
        s2 = ttk.Frame(sf); s2.pack(fill="x", pady=4)
        ttk.Label(s2, text="EPS:").pack(side="left")
        self.eps_var = tk.StringVar(value="10")
        tk.Spinbox(s2, from_=1, to=10000, width=8, textvariable=self.eps_var,
                   bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                   buttonbackground="#45475a", relief="flat", font=("Segoe UI", 10)).pack(side="left", padx=8)
        s3 = ttk.Frame(sf); s3.pack(pady=6)
        self.stream_btn = ttk.Button(s3, text="▶ Stream", style="Accent.TButton",
                                     command=self._toggle_stream)
        self.stream_btn.pack(side="left", padx=4)
        self.stream_stats = ttk.Label(sf, text="EPS: 0 | Total: 0", style="Sub.TLabel")
        self.stream_stats.pack(pady=4)

    def _root(self):
        return self.bulk_btn.winfo_toplevel()

    def _setup_ds(self, selected):
        for c in selected:
            if is_data_stream(self.cfg, c):
                idx = get_index(self.cfg, c)
                self._root().after(0, lambda n=idx: self.log(f"  🔧 DS '{n}'..."))
                ensure_data_stream(self.es, idx,
                    log_fn=lambda m: self._root().after(0, lambda msg=m: self.log(msg)))

    # ── Bulk ─────────────────────────────────────────────────
    def _start_bulk(self):
        sel = {k for k, v in self.log_vars.items() if v.get()}
        if not sel:
            messagebox.showwarning("", "Selecciona tipos."); return
        cts = {}
        for k in sel:
            try: cts[k] = int(self.log_counts[k].get())
            except: cts[k] = 500
        self.bulk_btn.configure(state="disabled")
        threading.Thread(target=self._bulk_worker, args=(sel, cts), daemon=True).start()

    def _bulk_worker(self, sel, cts):
        root = self._root()
        total = sum(cts.values()); done = 0
        root.after(0, lambda: self.bulk_prog.configure(maximum=total, value=0))
        root.after(0, lambda: self.log(f"Bulk — {total} eventos"))
        self._setup_ds(sel)
        for k in sel:
            n = cts[k]; gen = GENERATORS[k]; idx = get_index(self.cfg, k)
            ds = is_data_stream(self.cfg, k)
            root.after(0, lambda k=k, n=n: self.log(f"  {n} de '{k}'..."))
            docs = [gen(idx) for _ in range(n)]
            if ds:
                docs = [prepare_for_data_stream(d) for d in docs]
            try:
                ok, errs = helpers.bulk(self.es, docs, raise_on_error=False,
                                        chunk_size=200, request_timeout=120)
                en = len(errs) if isinstance(errs, list) else 0; done += ok
                root.after(0, lambda k=k, o=ok, e=en: self.log(f"  ✅ {k}: {o} ok, {e} err"))
            except Exception as ex:
                root.after(0, lambda k=k, x=str(ex)[:100]: self.log(f"  ❌ {k}: {x}"))
            root.after(0, lambda d=done: self.bulk_prog.configure(value=d))
        try:
            ni = ",".join(get_index(self.cfg, c) for c in sel if not is_data_stream(self.cfg, c))
            if ni: self.es.indices.refresh(index=ni)
        except: pass
        root.after(0, lambda: self.log(f"✅ Bulk — {done} docs"))
        root.after(0, lambda: self.bulk_btn.configure(state="normal"))

    # ── Stream ───────────────────────────────────────────────
    def _toggle_stream(self):
        if self.running:
            self._stop.set(); self.running = False
            self.stream_btn.configure(text="▶ Stream", style="Accent.TButton")
            self.log("⏹ Stop"); return
        sel = [k for k, v in self.stream_vars.items() if v.get()]
        if not sel:
            messagebox.showwarning("", "Selecciona tipos."); return
        try: eps = max(1, int(self.eps_var.get()))
        except: eps = 10
        self._stop.clear(); self.running = True
        self.stream_btn.configure(text="⏹ Detener", style="Danger.TButton")
        self.log(f"🌊 Stream {eps} EPS")
        threading.Thread(target=self._stream_worker, args=(sel, eps), daemon=True).start()

    def _stream_worker(self, sel, eps):
        root = self._root()
        self._setup_ds(sel)
        total = 0; bs = max(1, eps // 5) if eps > 200 else 1
        last_report = time.time(); events_since = 0
        gi = [(GENERATORS[c], get_index(self.cfg, c), is_data_stream(self.cfg, c)) for c in sel]
        while not self._stop.is_set():
            t0 = time.time(); docs = []
            for _ in range(bs):
                g, idx, ds = random.choice(gi)
                d = g(idx, ts=now_timestamp())
                if ds: d = prepare_for_data_stream(d)
                docs.append(d)
            try:
                if len(docs) == 1:
                    d = docs[0]; kw = {"index": d["_index"], "document": d["_source"]}
                    if d.get("_op_type") == "create": self.es.index(**kw, op_type="create")
                    else: self.es.index(**kw)
                else:
                    helpers.bulk(self.es, docs, raise_on_error=False, request_timeout=30)
                total += len(docs); events_since += len(docs)
            except Exception as ex:
                root.after(0, lambda x=str(ex)[:80]: self.log(f"  ⚠ {x}"))
                time.sleep(1); continue
            now = time.time()
            if now - last_report >= 2:
                ce = events_since / (now - last_report)
                root.after(0, lambda c=ce, t=total:
                    self.stream_stats.configure(text=f"EPS: {c:.1f} | Total: {t:,}"))
                events_since = 0; last_report = now
            elapsed = time.time() - t0
            sleep_time = (bs / eps) - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
        root.after(0, lambda t=total: self.log(f"  Total: {t:,}"))
        root.after(0, lambda t=total:
            self.stream_stats.configure(text=f"EPS: 0 | Total: {t:,} (stop)"))
