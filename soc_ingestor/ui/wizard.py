"""Configuration wizard — ES, Kibana, and Ingestion settings."""

import tkinter as tk
from tkinter import ttk, filedialog

from ..config import LOG_CATEGORIES


class WizardFrame:
    """Builds the 3-tab configuration wizard."""

    def __init__(self, root, cfg, on_save):
        self.root = root
        self.cfg = cfg
        self.on_save = on_save
        self.fields = {}
        self._build()

    def _build(self):
        ttk.Label(self.root, text="⚙  Configuración", style="Title.TLabel").pack(
            padx=15, pady=(12, 0), anchor="w")
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=12, pady=5)
        self._tab_es(nb)
        self._tab_kb(nb)
        self._tab_ingest(nb)
        bot = ttk.Frame(self.root, padding=8)
        bot.pack(fill="x")
        ttk.Button(bot, text="Guardar y continuar  →", style="Accent.TButton",
                   command=self._save).pack(side="right", padx=10)

    # ── Elasticsearch tab ────────────────────────────────────
    def _tab_es(self, nb):
        f = ttk.Frame(nb, padding=18)
        nb.add(f, text="  🔌 Elasticsearch  ")
        g = ttk.Frame(f); g.pack(fill="x", padx=15)
        r = 0
        for k, l, d in [("es_url", "URL Elasticsearch", "https://localhost:9200")]:
            ttk.Label(g, text=l + ":").grid(row=r, column=0, sticky="w", pady=5)
            e = ttk.Entry(g, width=50); e.insert(0, self.cfg.get(k, d))
            e.grid(row=r, column=1, sticky="ew", pady=5, padx=(8, 0))
            self.fields[k] = e; r += 1

        ttk.Label(g, text="Autenticación:").grid(row=r, column=0, sticky="w", pady=5)
        self.auth_var = tk.StringVar(value=self.cfg.get("auth_method", "apikey"))
        rf = ttk.Frame(g); rf.grid(row=r, column=1, sticky="w", pady=5)
        ttk.Radiobutton(rf, text="API Key", variable=self.auth_var, value="apikey",
                        command=self._toggle_auth).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(rf, text="User/Pass", variable=self.auth_var, value="basic",
                        command=self._toggle_auth).pack(side="left")
        r += 1

        for k, l, d, sh in [("api_key", "API Key", "", "*"),
                             ("es_user", "Usuario", "elastic", ""),
                             ("es_password", "Contraseña", "", "*")]:
            ttk.Label(g, text=l + ":").grid(row=r, column=0, sticky="w", pady=5)
            e = ttk.Entry(g, width=50, show=sh); e.insert(0, self.cfg.get(k, d))
            e.grid(row=r, column=1, sticky="ew", pady=5, padx=(8, 0))
            self.fields[k] = e; r += 1

        ttk.Label(g, text="CA cert:").grid(row=r, column=0, sticky="w", pady=5)
        e = ttk.Entry(g, width=50); e.insert(0, self.cfg.get("ca_cert", ""))
        e.grid(row=r, column=1, sticky="ew", pady=5, padx=(8, 0)); self.fields["ca_cert"] = e
        ttk.Button(g, text="📂", width=3,
                   command=lambda: self._browse(e)).grid(row=r, column=2, padx=4)
        r += 1

        self.verify_var = tk.BooleanVar(value=self.cfg.get("verify_certs", True))
        ttk.Checkbutton(g, text="Verificar SSL", variable=self.verify_var).grid(
            row=r, column=0, columnspan=2, sticky="w", pady=5)
        g.columnconfigure(1, weight=1)
        self._toggle_auth()

        bf = ttk.Frame(f); bf.pack(pady=12)
        ttk.Button(bf, text="Probar conexión ES", command=self._test_es).pack(side="left", padx=6)
        self.status_es = ttk.Label(f, text="", style="Sub.TLabel")
        self.status_es.pack()

    # ── Kibana tab ───────────────────────────────────────────
    def _tab_kb(self, nb):
        f = ttk.Frame(nb, padding=18)
        nb.add(f, text="  🌐 Kibana  ")
        ttk.Label(f, text="Usa las mismas credenciales de la pestaña ES.",
                  style="Sub.TLabel").pack(anchor="w", pady=(0, 12))
        g = ttk.Frame(f); g.pack(fill="x", padx=15)
        ttk.Label(g, text="URL Kibana:").grid(row=0, column=0, sticky="w", pady=5)
        e = ttk.Entry(g, width=50); e.insert(0, self.cfg.get("kb_url", ""))
        e.grid(row=0, column=1, sticky="ew", pady=5, padx=(8, 0)); self.fields["kb_url"] = e
        g.columnconfigure(1, weight=1)
        bf = ttk.Frame(f); bf.pack(pady=8)
        ttk.Button(bf, text="Probar conexión Kibana", command=self._test_kb).pack(side="left", padx=6)
        self.status_kb = ttk.Label(f, text="", style="Sub.TLabel")
        self.status_kb.pack()

    # ── Ingestion tab ────────────────────────────────────────
    def _tab_ingest(self, nb):
        f = ttk.Frame(nb, padding=15)
        nb.add(f, text="  📋 Config Ingesta  ")
        cv = tk.Canvas(f, bg="#1e1e2e", highlightthickness=0)
        sb = ttk.Scrollbar(f, orient="vertical", command=cv.yview)
        sf = ttk.Frame(cv)
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0, 0), window=sf, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.idx_entries = {}
        self.ds_vars = {}
        saved = self.cfg.get("indices", {})
        for cat, meta in LOG_CATEGORIES.items():
            sv = saved.get(cat, {})
            cf = ttk.LabelFrame(sf, text=f"  {meta['label']}  ", padding=8, style="C.TLabelframe")
            cf.pack(fill="x", padx=10, pady=5)
            r1 = ttk.Frame(cf, style="C.TLabelframe"); r1.pack(fill="x")
            ttk.Label(r1, text="Índice:", style="C.TLabel").pack(side="left")
            e = ttk.Entry(r1, width=38); e.insert(0, sv.get("name", meta["default_index"]))
            e.pack(side="left", padx=(8, 0)); self.idx_entries[cat] = e
            r2 = ttk.Frame(cf, style="C.TLabelframe"); r2.pack(fill="x", pady=(4, 0))
            dv = tk.BooleanVar(value=sv.get("data_stream", False)); self.ds_vars[cat] = dv
            ttk.Checkbutton(r2, text="Data Stream (auto-crea template)", variable=dv,
                            style="C.TCheckbutton").pack(side="left")

    # ── Helpers ──────────────────────────────────────────────
    def _toggle_auth(self):
        is_api = self.auth_var.get() == "apikey"
        for k in ("api_key",):
            if k in self.fields:
                self.fields[k].configure(state="normal" if is_api else "disabled")
        for k in ("es_user", "es_password"):
            if k in self.fields:
                self.fields[k].configure(state="disabled" if is_api else "normal")

    def _browse(self, entry):
        p = filedialog.askopenfilename(
            filetypes=[("Cert", "*.pem *.crt *.cer"), ("All", "*.*")])
        if p:
            entry.delete(0, "end"); entry.insert(0, p)

    def get_config(self) -> dict:
        c = {
            "es_url": self.fields["es_url"].get().strip(),
            "auth_method": self.auth_var.get(),
            "api_key": self.fields["api_key"].get().strip(),
            "es_user": self.fields["es_user"].get().strip(),
            "es_password": self.fields["es_password"].get().strip(),
            "ca_cert": self.fields["ca_cert"].get().strip(),
            "verify_certs": self.verify_var.get(),
            "kb_url": self.fields["kb_url"].get().strip(),
            "indices": {},
        }
        for cat in LOG_CATEGORIES:
            c["indices"][cat] = {
                "name": self.idx_entries[cat].get().strip() or LOG_CATEGORIES[cat]["default_index"],
                "data_stream": self.ds_vars[cat].get(),
            }
        return c

    def _test_es(self):
        from ..clients.elastic import create_client
        try:
            es = create_client(self.get_config())
            v = es.info()["version"]["number"]
            self.status_es.configure(text=f"✅ ES {v}", foreground="#a6e3a1")
        except Exception as ex:
            self.status_es.configure(text=f"❌ {str(ex)[:120]}", foreground="#f38ba8")

    def _test_kb(self):
        from ..clients.kibana import KibanaAPI
        c = self.get_config()
        if not c.get("kb_url"):
            self.status_kb.configure(text="❌ URL vacía", foreground="#f38ba8"); return
        try:
            kb = KibanaAPI(url=c["kb_url"], auth_method=c["auth_method"],
                           api_key=c["api_key"], user=c["es_user"],
                           password=c["es_password"], verify=c["verify_certs"],
                           ca=c["ca_cert"])
            st = kb.test_connection()
            v = st.get("version", {}).get("number", "?")
            self.status_kb.configure(text=f"✅ Kibana {v}", foreground="#a6e3a1")
        except Exception as ex:
            self.status_kb.configure(text=f"❌ {str(ex)[:120]}", foreground="#f38ba8")

    def _save(self):
        from tkinter import messagebox
        c = self.get_config()
        if not c["es_url"]:
            messagebox.showwarning("", "URL ES obligatoria."); return
        self.on_save(c)
