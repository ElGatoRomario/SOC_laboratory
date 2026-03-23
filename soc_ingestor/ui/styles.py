"""Catppuccin Mocha theme for ttk widgets."""

from tkinter import ttk


def apply_theme():
    s = ttk.Style()
    s.theme_use("clam")
    bg, fg, ac = "#1e1e2e", "#cdd6f4", "#89b4fa"

    s.configure(".", background=bg, foreground=fg, fieldbackground="#313244",
                borderwidth=0, font=("Segoe UI", 10))
    s.configure("TLabel", background=bg, foreground=fg)
    s.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground=ac, background=bg)
    s.configure("Sub.TLabel", font=("Segoe UI", 11, "bold"), foreground="#a6adc8", background=bg)
    s.configure("Small.TLabel", font=("Segoe UI", 9), foreground="#6c7086", background=bg)

    s.configure("TButton", background="#45475a", foreground=fg, padding=(12, 6),
                font=("Segoe UI", 10, "bold"))
    s.map("TButton", background=[("active", ac), ("disabled", "#313244")])
    s.configure("Accent.TButton", background=ac, foreground="#1e1e2e")
    s.map("Accent.TButton", background=[("active", "#74c7ec"), ("disabled", "#585b70")])
    s.configure("Danger.TButton", background="#f38ba8", foreground="#1e1e2e")
    s.map("Danger.TButton", background=[("active", "#eba0ac")])

    s.configure("TEntry", fieldbackground="#313244", foreground=fg, insertcolor=fg, padding=5)
    s.configure("TCheckbutton", background=bg, foreground=fg)
    s.map("TCheckbutton", background=[("active", bg)])
    s.configure("TLabelframe", background=bg, foreground=ac, font=("Segoe UI", 10, "bold"))
    s.configure("TLabelframe.Label", background=bg, foreground=ac)
    s.configure("TRadiobutton", background=bg, foreground=fg)
    s.map("TRadiobutton", background=[("active", bg)])
    s.configure("TCombobox", fieldbackground="#313244", foreground=fg, background="#45475a")

    s.configure("TNotebook", background=bg, borderwidth=0)
    s.configure("TNotebook.Tab", background="#313244", foreground=fg, padding=(12, 5),
                font=("Segoe UI", 10, "bold"))
    s.map("TNotebook.Tab", background=[("selected", "#45475a")], foreground=[("selected", ac)])

    s.configure("C.TLabelframe", background="#181825", foreground=ac)
    s.configure("C.TLabelframe.Label", background="#181825", foreground=ac,
                font=("Segoe UI", 10, "bold"))
    s.configure("C.TLabel", background="#181825", foreground=fg)
    s.configure("C.TCheckbutton", background="#181825", foreground=fg)
    s.map("C.TCheckbutton", background=[("active", "#181825")])

    s.configure("Treeview", background="#181825", foreground=fg, fieldbackground="#181825",
                rowheight=25, font=("Segoe UI", 9))
    s.configure("Treeview.Heading", background="#313244", foreground=ac,
                font=("Segoe UI", 9, "bold"))
    s.map("Treeview", background=[("selected", "#45475a")])
