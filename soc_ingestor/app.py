"""Main application — wires together config, UI, clients."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import threading

from .config import load_config, save_config, LOG_CATEGORIES, get_index, is_data_stream
from .clients.elastic import create_client
from .clients.kibana import KibanaAPI
from .ui.styles import apply_theme
from .ui.wizard import WizardFrame
from .ui.ingestion import IngestionPanel
from .ui.rules_panel import RulesPanel


class SOCIngestorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SOC Log Ingestor & Rule Manager")
        self.root.geometry("980x820")
        self.root.minsize(900, 750)
        self.root.configure(bg="#1e1e2e")
        self.es = None
        self.kb = None
        self.cfg = load_config()

        apply_theme()
        self._check_deps()

        if self.cfg.get("es_url"):
            self._build_main()
        else:
            self._build_wizard()

    def _check_deps(self):
        missing = []
        try:
            import elasticsearch
        except ImportError:
            missing.append("elasticsearch>=8,<9")
        try:
            import faker
        except ImportError:
            missing.append("faker")
        if missing:
            messagebox.showerror("Dependencias",
                f"Instala:\n\npip install {' '.join(missing)}")
            self.root.destroy()
            raise SystemExit

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    # ── Wizard ───────────────────────────────────────────────
    def _build_wizard(self):
        self._clear()
        self.wizard = WizardFrame(self.root, self.cfg, self._on_wizard_save)

    def _on_wizard_save(self, cfg):
        try:
            es = create_client(cfg); es.info(); self.es = es
        except Exception as ex:
            if not messagebox.askyesno("ES", f"Sin conexión:\n{str(ex)[:200]}\n\n¿Guardar?"):
                return
        if cfg.get("kb_url"):
            self.kb = self._make_kb(cfg)
        self.cfg = cfg
        save_config(cfg)
        self._build_main()

    def _make_kb(self, cfg):
        return KibanaAPI(
            url=cfg.get("kb_url", ""),
            auth_method=cfg.get("auth_method", "basic"),
            api_key=cfg.get("api_key", ""),
            user=cfg.get("es_user", ""),
            password=cfg.get("es_password", ""),
            verify=cfg.get("verify_certs", True),
            ca=cfg.get("ca_cert", ""),
        )

    # ── Main UI ──────────────────────────────────────────────
    def _build_main(self):
        self._clear()

        # Top bar
        top = ttk.Frame(self.root, padding=(12, 8)); top.pack(fill="x")
        ttk.Label(top, text="🛡  SOC Log Ingestor & Rule Manager",
                  style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="⚙ Config", command=self._build_wizard).pack(side="right")
        self.status = ttk.Label(top, text="", style="Sub.TLabel")
        self.status.pack(side="right", padx=12)

        # Connect ES (client creation only — probe runs in background)
        if not self.es:
            try:
                self.es = create_client(self.cfg)
            except Exception:
                pass

        if not self.kb and self.cfg.get("kb_url"):
            self.kb = self._make_kb(self.cfg)

        # Main notebooks
        mnb = ttk.Notebook(self.root)
        mnb.pack(fill="both", expand=True, padx=10, pady=(4, 2))

        # Ingestion section
        ing_f = ttk.Frame(mnb); mnb.add(ing_f, text="  📦 Ingesta  ")
        ing_nb = ttk.Notebook(ing_f)
        ing_nb.pack(fill="both", expand=True, padx=4, pady=4)
        self.ingestion = IngestionPanel(ing_nb, self.cfg, self.es, self._log)

        # Rules section
        rul_f = ttk.Frame(mnb); mnb.add(rul_f, text="  🔒 Reglas MITRE ATT&CK  ")
        rul_nb = ttk.Notebook(rul_f)
        rul_nb.pack(fill="both", expand=True, padx=4, pady=4)
        self.rules = RulesPanel(rul_nb, self.cfg, self.kb, self._log)

        # Console
        clf = ttk.LabelFrame(self.root, text="  📋 Consola  ", padding=4)
        clf.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.console = scrolledtext.ScrolledText(
            clf, height=6, bg="#11111b", fg="#a6adc8",
            insertbackground="#cdd6f4", font=("Consolas", 9),
            relief="flat", wrap="word")
        self.console.pack(fill="both", expand=True)

        self._log("Aplicación iniciada.")
        kb_st = "configurado" if self.cfg.get("kb_url") else "no configurado"
        self._log(f"  Kibana: {kb_st}")
        for cat in LOG_CATEGORIES:
            m = "DS" if is_data_stream(self.cfg, cat) else "idx"
            self._log(f"  {LOG_CATEGORIES[cat]['label']} → {get_index(self.cfg, cat)} ({m})")

        threading.Thread(target=self._connect_bg, daemon=True).start()

    def _connect_bg(self):
        """Background thread: probe ES/Kibana without blocking the UI."""
        if self.es:
            try:
                v = self.es.info()["version"]["number"]
                self.root.after(0, lambda: self.status.configure(
                    text=f"ES {v}", foreground="#a6e3a1"))
            except Exception:
                self.root.after(0, lambda: self.status.configure(
                    text="Sin ES", foreground="#f38ba8"))
        else:
            self.root.after(0, lambda: self.status.configure(
                text="Sin ES", foreground="#f38ba8"))
        if self.kb:
            self.root.after(0, self.rules.load_spaces)

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] {msg}\n")
        self.console.see("end")


def main():
    root = tk.Tk()
    root.tk.call("tk", "scaling", 1.25)
    _ = SOCIngestorApp(root)
    root.mainloop()
