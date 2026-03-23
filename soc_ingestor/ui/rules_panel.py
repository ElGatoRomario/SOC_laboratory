"""Rules & Alerts UI — Generate, list, delete rules; fetch alerts."""

import tkinter as tk
from tkinter import ttk, messagebox
import threading

from ..rules.mitre import MITRE_TACTICS, TACTIC_ICONS
from ..rules.builder import build_all_rules, to_kibana_body


class RulesPanel:
    """Builds Generate + Alerts sub-tabs inside a parent notebook."""

    def __init__(self, parent_nb, cfg, kb, log_fn):
        self.cfg = cfg
        self.kb = kb
        self.log = log_fn
        self.spaces_cache = []
        self._build(parent_nb)

    def _build(self, nb):
        # ── Generate tab ─────────────────────────────────────
        gf = ttk.Frame(nb, padding=10); nb.add(gf, text="  ⚡ Generar  ")
        spf = ttk.Frame(gf); spf.pack(fill="x", pady=(0, 8))
        ttk.Label(spf, text="Kibana Space:").pack(side="left")
        self.sp_gen = ttk.Combobox(spf, state="readonly", width=30)
        self.sp_gen.pack(side="left", padx=8)
        ttk.Button(spf, text="🔄 Cargar spaces", command=self.load_spaces).pack(side="left", padx=4)

        tf = ttk.LabelFrame(gf, text="  Tácticas MITRE ATT&CK  ", padding=8)
        tf.pack(fill="x", pady=(0, 6))
        self.tactic_vars = {}; tgf = ttk.Frame(tf); tgf.pack(fill="x")
        for i, tac in enumerate(MITRE_TACTICS):
            v = tk.BooleanVar(value=True); self.tactic_vars[tac] = v
            ttk.Checkbutton(tgf, text=f"{TACTIC_ICONS.get(tac, '')} {tac}",
                            variable=v).grid(row=i // 3, column=i % 3, sticky="w", padx=6, pady=2)

        gbf = ttk.Frame(gf); gbf.pack(pady=8)
        ttk.Button(gbf, text="▶ Generar reglas", style="Accent.TButton",
                   command=self._gen_rules).pack(side="left", padx=4)
        ttk.Button(gbf, text="🗑 Eliminar reglas SOC", style="Danger.TButton",
                   command=self._del_rules).pack(side="left", padx=4)
        ttk.Button(gbf, text="🔄 Refrescar lista",
                   command=self._refresh_tree).pack(side="left", padx=4)

        rlf = ttk.LabelFrame(gf, text="  Reglas en Kibana  ", padding=4)
        rlf.pack(fill="both", expand=True, pady=(6, 0))
        rc = ("id", "name", "tactic", "severity", "enabled")
        self.rtree = ttk.Treeview(rlf, columns=rc, show="headings", height=7)
        for c, w in [("id", 85), ("name", 260), ("tactic", 130), ("severity", 70), ("enabled", 60)]:
            self.rtree.heading(c, text=c.title()); self.rtree.column(c, width=w, minwidth=40)
        rsb = ttk.Scrollbar(rlf, orient="vertical", command=self.rtree.yview)
        self.rtree.configure(yscrollcommand=rsb.set)
        self.rtree.pack(side="left", fill="both", expand=True); rsb.pack(side="right", fill="y")
        for sev, color in [("critical", "#f38ba8"), ("high", "#fab387"),
                           ("medium", "#f9e2af"), ("low", "#a6e3a1")]:
            self.rtree.tag_configure(sev, foreground=color)

        nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # ── Alerts tab ───────────────────────────────────────
        af = ttk.Frame(nb, padding=10); nb.add(af, text="  🚨 Alertas  ")

        aspf = ttk.Frame(af); aspf.pack(fill="x", pady=(0, 4))
        ttk.Label(aspf, text="Kibana Space:").pack(side="left")
        self.sp_al = ttk.Combobox(aspf, state="readonly", width=30)
        self.sp_al.pack(side="left", padx=8)
        ttk.Button(aspf, text="🔄", command=self.load_spaces).pack(side="left", padx=2)
        ttk.Button(aspf, text="▶ Buscar alertas", style="Accent.TButton",
                   command=self._fetch_alerts).pack(side="left", padx=8)

        # Filters — use OptionMenu instead of Combobox to avoid the Windows
        # CBS_DROPDOWNLIST focus-clearing bug when multiple dropdowns share a tab.
        aff = ttk.Frame(af); aff.pack(fill="x", pady=(0, 6))
        _om_kw = dict(bg="#45475a", fg="#cdd6f4", activebackground="#89b4fa",
                      activeforeground="#1e1e2e", relief="flat", bd=0,
                      highlightthickness=0, font=("Segoe UI", 10), width=16)
        _mn_kw = dict(bg="#313244", fg="#cdd6f4", activebackground="#89b4fa",
                      activeforeground="#1e1e2e", font=("Segoe UI", 10))

        ttk.Label(aff, text="Estado:").pack(side="left")
        self._al_status_var = tk.StringVar(value="Todas")
        om_status = tk.OptionMenu(aff, self._al_status_var,
                                  "Todas", "open", "closed", "acknowledged")
        om_status.configure(**_om_kw); om_status["menu"].configure(**_mn_kw)
        om_status.pack(side="left", padx=8)

        ttk.Label(aff, text="Período:").pack(side="left", padx=(12, 0))
        self._al_time_var = tk.StringVar(value="Todo")
        om_time = tk.OptionMenu(aff, self._al_time_var,
                                "Todo", "Última hora", "Últimas 6h", "Últimas 24h",
                                "Últimos 7 días", "Últimos 30 días")
        om_time.configure(**_om_kw); om_time["menu"].configure(**_mn_kw)
        om_time.pack(side="left", padx=8)

        self.alert_lbl = ttk.Label(af, text="", style="Sub.TLabel"); self.alert_lbl.pack(pady=2)

        ac = ("timestamp", "severity", "rule", "tactic", "host", "source_ip")
        self.atree = ttk.Treeview(af, columns=ac, show="headings", height=10)
        for c, w in [("timestamp", 140), ("severity", 70), ("rule", 230),
                     ("tactic", 120), ("host", 100), ("source_ip", 110)]:
            self.atree.heading(c, text=c.replace("_", " ").title())
            self.atree.column(c, width=w, minwidth=40)
        asb = ttk.Scrollbar(af, orient="vertical", command=self.atree.yview)
        self.atree.configure(yscrollcommand=asb.set)
        self.atree.pack(side="left", fill="both", expand=True); asb.pack(side="right", fill="y")
        for sev, color in [("critical", "#f38ba8"), ("high", "#fab387"),
                           ("medium", "#f9e2af"), ("low", "#a6e3a1")]:
            self.atree.tag_configure(sev, foreground=color)

    def _on_tab_changed(self, event):
        nb = event.widget
        if nb.index("current") == 0 and self.kb:
            sid = self._sel_space(self.sp_gen)
            if sid:
                threading.Thread(target=self._refresh_tree_bg, args=(sid,), daemon=True).start()

    def _root(self):
        return self.rtree.winfo_toplevel()

    def _sel_space(self, combo):
        val = combo.get()
        if not val: return None
        return val.split(" — ")[0].strip()

    def load_spaces(self):
        if not self.kb: return
        try:
            spaces = self.kb.list_spaces()
            self.spaces_cache = spaces
            names = [f"{s['id']} — {s['name']}" for s in spaces]
            for cb in [self.sp_gen, self.sp_al]:
                cb["values"] = names
                if names: cb.current(0)
            self.log(f"  📂 {len(spaces)} spaces descubiertos")
        except Exception as ex:
            self.log(f"  ⚠ Spaces: {str(ex)[:100]}")

    # ── Generate rules ───────────────────────────────────────
    def _gen_rules(self):
        sid = self._sel_space(self.sp_gen)
        if not sid: messagebox.showwarning("", "Selecciona Space."); return
        sel = {t for t, v in self.tactic_vars.items() if v.get()}
        if not sel: messagebox.showwarning("", "Selecciona tácticas."); return
        threading.Thread(target=self._gen_worker, args=(sid, sel), daemon=True).start()

    def _gen_worker(self, sid, sel):
        root = self._root()
        root.after(0, lambda: self.log(f"⚡ Generando reglas en '{sid}'..."))
        all_r = build_all_rules(self.cfg)
        filtered = [r for r in all_r if r["tactic"] in sel]
        ok = err = 0
        for r in filtered:
            body = to_kibana_body(r)
            try:
                self.kb.create_rule(sid, body); ok += 1
                root.after(0, lambda n=r["name"]: self.log(f"  ✅ {n}"))
            except Exception as ex:
                estr = str(ex)
                if "already" in estr.lower() or "409" in estr:
                    try:
                        self.kb.delete_rule(sid, r["rule_id"])
                        self.kb.create_rule(sid, body); ok += 1
                        root.after(0, lambda n=r["name"]: self.log(f"  🔄 {n} (actualizada)"))
                    except Exception as ex2:
                        err += 1; root.after(0, lambda n=r["rule_id"], x=str(ex2)[:80]: self.log(f"  ❌ {n}: {x}"))
                else:
                    err += 1; root.after(0, lambda n=r["rule_id"], x=estr[:80]: self.log(f"  ❌ {n}: {x}"))
        root.after(0, lambda: self.log(f"✅ {ok} creadas, {err} errores"))
        root.after(0, lambda: self._refresh_tree(sid))

    def _del_rules(self):
        sid = self._sel_space(self.sp_gen)
        if not sid: return
        if not messagebox.askyesno("", "¿Eliminar reglas SOC-Ingestor?"): return
        threading.Thread(target=self._del_worker, args=(sid,), daemon=True).start()

    def _del_worker(self, sid):
        root = self._root()
        root.after(0, lambda: self.log(f"🗑 Eliminando en '{sid}'..."))
        try:
            res = self.kb.find_rules(sid)
            soc = [r for r in res.get("data", []) if "SOC-Ingestor" in (r.get("tags") or [])]
            for r in soc:
                try:
                    self.kb.delete_rule(sid, r.get("rule_id", ""))
                    root.after(0, lambda n=r.get("name", "?"): self.log(f"  🗑 {n}"))
                except Exception as ex:
                    root.after(0, lambda x=str(ex)[:80]: self.log(f"  ⚠ {x}"))
            root.after(0, lambda n=len(soc): self.log(f"✅ {n} eliminadas"))
            root.after(0, lambda: self._refresh_tree(sid))
        except Exception as ex:
            root.after(0, lambda x=str(ex)[:120]: self.log(f"❌ {x}"))

    def _refresh_tree(self, sid=None):
        if not sid:
            sid = self._sel_space(self.sp_gen)
        if not sid or not self.kb:
            return
        threading.Thread(target=self._refresh_tree_bg, args=(sid,), daemon=True).start()

    def _refresh_tree_bg(self, sid):
        root = self._root()
        try:
            res = self.kb.find_rules(sid)
            rows = []
            for r in res.get("data", []):
                sev = r.get("severity", "medium")
                threat = r.get("threat", [])
                tac = threat[0]["tactic"]["name"] if threat else ""
                rows.append((r.get("rule_id", ""), r.get("name", ""), tac,
                             sev.upper(), "✅" if r.get("enabled") else "❌", sev))

            def _update():
                for i in self.rtree.get_children():
                    self.rtree.delete(i)
                for *vals, sev in rows:
                    self.rtree.insert("", "end", values=vals, tags=(sev,))

            root.after(0, _update)
        except Exception as ex:
            root.after(0, lambda x=str(ex)[:80]: self.log(f"  ⚠ {x}"))

    _TIME_MAP = {
        "Todo": None, "Última hora": "1h", "Últimas 6h": "6h",
        "Últimas 24h": "24h", "Últimos 7 días": "7d", "Últimos 30 días": "30d",
    }

    # ── Fetch alerts ─────────────────────────────────────────
    def _fetch_alerts(self):
        sid = self._sel_space(self.sp_al)
        if not sid: messagebox.showwarning("", "Selecciona Space."); return
        status_val = self._al_status_var.get()
        status = None if status_val == "Todas" else status_val
        time_range = self._TIME_MAP.get(self._al_time_var.get())
        threading.Thread(target=self._alerts_worker,
                         args=(sid, status, time_range), daemon=True).start()

    def _alerts_worker(self, sid, status=None, time_range=None):
        root = self._root()
        root.after(0, lambda: self.log(f"🔍 Alertas en '{sid}'..."))
        try:
            res = self.kb.search_alerts(sid, size=200, status=status, time_range=time_range)
            hits = res.get("hits", {}).get("hits", [])

            def _update():
                for i in self.atree.get_children(): self.atree.delete(i)
                for h in hits:
                    s = h.get("_source", {})
                    ts = s.get("@timestamp", "")[:19].replace("T", " ")
                    sig = s.get("signal", {}).get("rule", {})
                    sev = sig.get("severity", s.get("kibana.alert.severity", "medium"))
                    rule = sig.get("name", s.get("kibana.alert.rule.name", "Unknown"))
                    threat = sig.get("threat", [])
                    tac = threat[0]["tactic"]["name"] if threat else ""
                    host = (s.get("host", {}).get("name", "")
                            if isinstance(s.get("host"), dict) else s.get("host.name", ""))
                    src = (s.get("source", {}).get("ip", "")
                           if isinstance(s.get("source"), dict) else s.get("source.ip", ""))
                    self.atree.insert("", "end",
                        values=(ts, sev.upper(), rule, tac, host, src), tags=(sev,))
                self.alert_lbl.configure(
                    text=f"🚨 {len(hits)} alertas",
                    foreground="#f38ba8" if hits else "#a6e3a1")

            root.after(0, lambda: self.log(f"  🚨 {len(hits)} alertas"))
            root.after(0, _update)
        except Exception as ex:
            root.after(0, lambda x=str(ex)[:150]: self.log(f"❌ {x}"))
