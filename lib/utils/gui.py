#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import subprocess
import sys
import tempfile
import threading
import webbrowser

from lib.core.common import getSafeExString
from lib.core.common import saveConfig
from lib.core.data import paths
from lib.core.defaults import defaults
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapSystemException
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import IS_WIN
from lib.core.settings import ISSUES_PAGE
from lib.core.settings import GIT_PAGE
from lib.core.settings import SITE
from lib.core.settings import VERSION_STRING
from lib.core.settings import WIKI_PAGE
from thirdparty.six.moves import queue as _queue

# Classic Windows (NT/9x) palette: silver 3D face, navy title/selection, white sunken fields,
# black text, and saturated VGA-style accents for the icons (presentation only)
PALETTE = {
    "base": "#c0c0c0",        # window / control face (silver)
    "mantle": "#c0c0c0",      # bars (classic is uniform gray, separated by bevels)
    "crust": "#ffffff",       # console / edit background
    "surface0": "#ffffff",    # field (edit) background
    "surface1": "#808080",    # 3D shadow
    "surface2": "#dfdfdf",    # 3D light (soft)
    "light": "#ffffff",       # 3D highlight
    "dark": "#404040",        # 3D dark shadow
    "text": "#000000",
    "subtext": "#000000",
    "overlay": "#404040",
    "title2": "#1084d0",      # active title-bar gradient end
    "blue": "#000080",        # navy: title, selection, accents
    "sapphire": "#0050b0",
    "sky": "#0070c0",
    "green": "#008000",
    "teal": "#008080",
    "red": "#c00000",
    "maroon": "#800000",
    "mauve": "#9000a8",
    "pink": "#c000b0",
    "peach": "#c06000",
    "yellow": "#c08000",
    "lavender": "#4858c0",
    "flamingo": "#c04070",
    "gold": "#e0a800",
}

# a distinct accent color per section, so the sidebar icons read as a colorful, scannable set
ICON_COLORS = {
    "Quick start": "yellow",
    "Target": "red",
    "Request": "sapphire",
    "Optimization": "teal",
    "Injection": "mauve",
    "Detection": "sky",
    "Techniques": "maroon",
    "Fingerprint": "lavender",
    "Enumeration": "green",
    "Brute force": "peach",
    "User-defined function injection": "pink",
    "File system access": "gold",
    "Operating system access": "blue",
    "Windows registry access": "sapphire",
    "General": "teal",
    "Miscellaneous": "overlay",
}

# Options surfaced on the curated "Quick start" pane (by destination), in display order
QUICK_START_DESTS = (
    "data", "cookie", "dbms", "level", "risk", "technique",
    "getCurrentUser", "getCurrentDb", "getBanner", "isDba",
    "getDbs", "getTables", "getColumns", "getPasswordHashes", "dumpTable",
    "batch", "threads", "proxy", "tor",
)

# Short, readable sidebar labels for the (sometimes verbose) option-group titles
NAV_ALIASES = {
    "User-defined function injection": "UDF injection",
    "Operating system access": "OS access",
    "Windows registry access": "Windows registry",
    "File system access": "File system",
}

TARGET_PLACEHOLDER = "http://www.target.com/vuln.php?id=1"

HINT_DEFAULT = "Hover or focus a field to see what it does."

# --- parser-backend compatibility (works for both optparse and argparse objects) ---

def _parserGroups(parser):
    groups = getattr(parser, "option_groups", None)
    if groups is None:
        groups = [_ for _ in getattr(parser, "_action_groups", []) if getattr(_, "title", None) not in (None, "positional arguments", "optional arguments", "options")]
    return groups or []

def _groupOptions(group):
    for attr in ("option_list", "_group_actions"):
        if hasattr(group, attr):
            return getattr(group, attr)
    return []

def _groupTitle(group):
    return getattr(group, "title", "") or ""

def _groupDescription(group):
    if hasattr(group, "get_description"):
        return group.get_description() or ""
    return getattr(group, "description", "") or ""

def _optStrings(option):
    if hasattr(option, "option_strings"):                                  # argparse
        return list(option.option_strings)
    return list(getattr(option, "_short_opts", None) or []) + list(getattr(option, "_long_opts", None) or [])

def _optDest(option):
    return getattr(option, "dest", None)

def _optHelp(option):
    return getattr(option, "help", "") or ""

def _optChoices(option):
    return getattr(option, "choices", None)

def _optTakesValue(option):
    if hasattr(option, "takes_value"):                                     # optparse Option
        try:
            return option.takes_value()
        except Exception:
            pass
    return getattr(option, "nargs", 1) != 0                                # argparse: store_true/false has nargs 0

def _optValueType(option):
    kind = getattr(option, "type", None)
    if kind in ("int", int):
        return "int"
    if kind in ("float", float):
        return "float"
    return "string"

def _optionLabel(option):
    return ", ".join(_optStrings(option)) or (_optDest(option) or "")

class _Tooltip(object):
    """Lightweight hover tooltip for a widget"""

    def __init__(self, widget, text, tk, palette):
        self._widget = widget
        self._text = text
        self._tk = tk
        self._palette = palette
        self._tip = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, event=None):
        if self._tip or not self._text:
            return
        x = self._widget.winfo_rootx() + 18
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 6
        self._tip = tw = self._tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        self._tk.Label(tw, text=self._text, justify="left", background=self._palette["surface0"],
                       foreground=self._palette["text"], relief="flat", borderwidth=0,
                       wraplength=460, padx=10, pady=7).pack()

    def _hide(self, event=None):
        if self._tip:
            self._tip.destroy()
            self._tip = None

class SqlmapGui(object):
    def __init__(self, parser, tk, ttk, scrolledtext, messagebox, filedialog, font):
        self.parser = parser
        self.tk = tk
        self.ttk = ttk
        self.scrolledtext = scrolledtext
        self.messagebox = messagebox
        self.filedialog = filedialog
        self.font = font

        self.widgets = {}                # dest -> (type, shared Tk variable)
        self.vars = {}                   # dest -> shared Tk variable (one per option, bound to every widget for it)
        self.optionByDest = {}
        for group in _parserGroups(parser):
            for option in _groupOptions(group):
                if _optDest(option):
                    self.optionByDest[_optDest(option)] = option

        self.panes = {}                  # name -> outer frame
        self.navItems = {}               # name -> (row frame, accent strip, icon canvas, label)
        self.canvases = {}               # name -> canvas (for wheel binding)
        self.inners = {}                 # name -> scrollable inner frame (populated lazily)
        self.builders = {}               # name -> callable that populates the inner frame
        self.built = set()               # names whose content has been built
        self.badges = {}                 # name -> sidebar count badge label
        self.sectionDests = {}           # name -> [option dests in that section]
        self.paneOrder = []              # nav order, for Up/Down navigation
        self.currentPane = None
        self.process = None
        self.alive = False
        self.queue = None

        try:
            self.window = tk.Tk()
        except Exception as ex:
            raise SqlmapSystemException("unable to create GUI window ('%s')" % getSafeExString(ex))

        self._initFonts()
        self._initStyle()
        self._buildLayout()

    def _initFonts(self):
        family = self.font.nametofont("TkDefaultFont").actual("family")
        self.fonts = {
            "body": (family, 10),
            "bodyBold": (family, 10, "bold"),
            "small": (family, 9),
            "nav": (family, 10),
            "title": (family, 18, "bold"),
            "subtitle": (family, 9),
            "mono": (self.font.nametofont("TkFixedFont").actual("family"), 10),
        }

    def _initStyle(self):
        p = PALETTE
        face, light, light2, shadow, dark = p["base"], p["light"], p["surface2"], p["surface1"], p["dark"]
        navy, white, black, field = p["blue"], "#ffffff", p["text"], p["surface0"]
        style = self.ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=face, foreground=black, fieldbackground=field,
                        bordercolor=shadow, lightcolor=light, darkcolor=shadow,
                        troughcolor=face, focuscolor=face, insertcolor=black, font=self.fonts["body"])

        for name in ("TFrame", "Bar.TFrame", "Nav.TFrame", "Card.TFrame"):
            style.configure(name, background=face)

        style.configure("TLabel", background=face, foreground=black)
        style.configure("Title.TLabel", background=navy, foreground=white, font=self.fonts["title"])
        style.configure("Subtitle.TLabel", background=navy, foreground=white, font=self.fonts["subtitle"])
        style.configure("Hint.TLabel", background=face, foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Field.TLabel", background=face, foreground=black)
        style.configure("Desc.TLabel", background=face, foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Pane.TLabel", background=face, foreground=navy, font=self.fonts["title"])
        style.configure("Stat.TLabel", background=face, foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Prompt.TLabel", background=field, foreground=black, font=self.fonts["mono"])

        # classic raised 3D push button
        style.configure("TButton", background=face, foreground=black, relief="raised", borderwidth=2,
                        lightcolor=light, darkcolor=dark, bordercolor=shadow, focuscolor=black, padding=(12, 4))
        style.map("TButton", background=[("active", face)], relief=[("pressed", "sunken")])

        # sunken white edit fields
        for name in ("TEntry", "Target.TEntry"):
            style.configure(name, fieldbackground=field, foreground=black, relief="sunken", borderwidth=2,
                            bordercolor=shadow, lightcolor=shadow, darkcolor=light, insertcolor=black, padding=4)

        style.configure("TCheckbutton", background=face, foreground=black, focuscolor=face, padding=2,
                        indicatorbackground=field, indicatorforeground=black, indicatorrelief="sunken", indicatorborderwidth=2,
                        bordercolor=shadow, lightcolor=shadow, darkcolor=light)
        style.map("TCheckbutton", background=[("active", face)], indicatorbackground=[("active", field), ("selected", field)])

        style.configure("TCombobox", fieldbackground=field, background=face, foreground=black, arrowcolor=black,
                        relief="sunken", borderwidth=2, bordercolor=shadow, lightcolor=shadow, darkcolor=light, padding=3)

        # classic chunky scrollbar (raised gray thumb, light trough)
        style.configure("Vertical.TScrollbar", background=face, troughcolor=light2, bordercolor=shadow,
                        lightcolor=light, darkcolor=dark, arrowcolor=black, relief="raised", width=17)
        style.map("Vertical.TScrollbar", background=[("active", face)])

        self.window.configure(background=face)

    # --- layout ---------------------------------------------------------

    def _buildLayout(self):
        tk = self.tk
        self.window.title("sqlmap")
        self.window.minsize(960, 680)
        self._buildMenu()
        self._buildHeader()

        target = self.ttk.Frame(self.window, style="Bar.TFrame", padding=(20, 12, 20, 14))
        target.pack(fill=tk.X)
        labelRow = self.ttk.Frame(target, style="Bar.TFrame")
        labelRow.pack(fill=tk.X, pady=(0, 4))
        self.ttk.Label(labelRow, text="TARGET URL", style="Hint.TLabel").pack(side=tk.LEFT)
        self.ttk.Label(labelRow, text="   e.g.  %s" % TARGET_PLACEHOLDER, style="Stat.TLabel").pack(side=tk.LEFT)
        urlVar = self._destVar("url", False)
        self.targetEntry = self.ttk.Entry(target, style="Target.TEntry", textvariable=urlVar)
        self.targetEntry.pack(fill=tk.X, ipady=2)
        self.widgets["url"] = ("string", urlVar)

        body = self.ttk.Frame(self.window, style="TFrame")
        body.pack(expand=True, fill=tk.BOTH)

        navHolder = self.ttk.Frame(body, style="Nav.TFrame", width=202)
        navHolder.pack(side=tk.LEFT, fill=tk.Y)
        navHolder.pack_propagate(False)
        self.navCanvas = tk.Canvas(navHolder, background=PALETTE["mantle"], highlightthickness=0, borderwidth=0)
        navScroll = self.ttk.Scrollbar(navHolder, orient="vertical", command=self.navCanvas.yview, style="Vertical.TScrollbar")
        self.nav = self.ttk.Frame(self.navCanvas, style="Nav.TFrame")
        self.nav.bind("<Configure>", lambda e: self.navCanvas.configure(scrollregion=self.navCanvas.bbox("all")))
        navWin = self.navCanvas.create_window((0, 0), window=self.nav, anchor="nw")
        self.navCanvas.bind("<Configure>", lambda e: self.navCanvas.itemconfigure(navWin, width=e.width))
        self.navCanvas.configure(yscrollcommand=navScroll.set)
        self.navCanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        navScroll.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Frame(body, background=PALETTE["surface1"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        self.content = self.ttk.Frame(body, style="Card.TFrame")
        self.content.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        cmdBar = self.ttk.Frame(self.window, style="Bar.TFrame", padding=(20, 8))
        cmdBar.pack(fill=tk.X)
        self.ttk.Label(cmdBar, text="Command:", style="Hint.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        self.ttk.Button(cmdBar, text="Copy", command=self._copyCommand, takefocus=False).pack(side=tk.RIGHT, padx=(8, 0))
        self.command = tk.StringVar(value="sqlmap.py")
        cmdEntry = tk.Entry(cmdBar, textvariable=self.command, font=self.fonts["mono"],
                            bg="#ffffff", fg=PALETTE["blue"], readonlybackground="#ffffff",
                            disabledforeground=PALETTE["blue"], relief="sunken", borderwidth=2,
                            highlightthickness=0, state="readonly")
        cmdEntry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        hintBar = self.ttk.Frame(self.window, style="Bar.TFrame", padding=(20, 9))
        hintBar.pack(fill=tk.X)
        self.stat = tk.StringVar(value="")
        self.ttk.Label(hintBar, textvariable=self.stat, style="Stat.TLabel", anchor="e").pack(side=tk.RIGHT, padx=(12, 0))
        self.hint = tk.StringVar(value=HINT_DEFAULT)
        self.ttk.Label(hintBar, textvariable=self.hint, style="Hint.TLabel", anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._buildQuickStartPane()
        for group in _parserGroups(self.parser):
            self._buildGroupPane(group)

        self._selectPane("Quick start")
        self.window.bind("<Down>", lambda e: self._navKey(1))
        self.window.bind("<Up>", lambda e: self._navKey(-1))
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.window.bind_all(seq, self._onWheel)
        self.window.bind("<F5>", lambda e: self.run())
        self.window.bind("<Control-r>", lambda e: self.run())
        self.window.bind("<Control-Return>", lambda e: self.run())
        self.window.bind("<Control-l>", lambda e: self._focusTarget())
        self.window.bind("<Control-s>", lambda e: self.saveConfigDialog())
        self.window.bind("<Control-o>", lambda e: self.loadConfig())
        self._enableSelectAll()
        self._tickStats()
        self._prebuildPanes()
        self._center(self.window, 1000, 720)

    def _prebuildPanes(self):
        # Tk isn't thread-safe, so widgets must be built on the main thread; instead of blocking,
        # build the not-yet-visited panes one per idle tick so they are ready (instant) by the time
        # the user navigates to them, while the UI stays responsive (on-demand build is the fallback)
        pending = [_ for _ in self.paneOrder if _ not in self.built]

        def step():
            while pending and pending[0] in self.built:
                pending.pop(0)
            if not pending:
                return
            name = pending.pop(0)
            try:
                self.builders[name](self.inners[name])
                self.built.add(name)
            except Exception:
                pass
            if pending:
                self.window.after(30, step)

        self.window.after(250, step)

    def _enableSelectAll(self):
        # Tk binds Ctrl-A to "cursor to line start" by default; rebind it to select-all,
        # which is what users expect (covers entries, comboboxes and the console text widget)
        def selectEntry(event):
            try:
                event.widget.select_range(0, "end")
                event.widget.icursor("end")
            except Exception:
                pass
            return "break"

        def selectText(event):
            try:
                event.widget.tag_add("sel", "1.0", "end-1c")
            except Exception:
                pass
            return "break"

        for cls in ("TEntry", "Entry", "TCombobox"):
            self.window.bind_class(cls, "<Control-a>", selectEntry)
            self.window.bind_class(cls, "<Control-A>", selectEntry)
        for seq in ("<Control-a>", "<Control-A>"):
            self.window.bind_class("Text", seq, selectText)

    def _buildMenu(self):
        p = PALETTE
        menubar = self.tk.Menu(self.window, bg=p["mantle"], fg=p["text"], activebackground=p["surface0"], activeforeground=p["text"], borderwidth=0)
        filemenu = self.tk.Menu(menubar, tearoff=0, bg=p["mantle"], fg=p["text"], activebackground=p["surface0"], activeforeground=p["text"])
        filemenu.add_command(label="Load configuration...", command=self.loadConfig)
        filemenu.add_command(label="Save configuration...", command=self.saveConfigDialog)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.window.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        menubar.add_command(label="Run", command=self.run)
        helpmenu = self.tk.Menu(menubar, tearoff=0, bg=p["mantle"], fg=p["text"], activebackground=p["surface0"], activeforeground=p["text"])
        helpmenu.add_command(label="Official site", command=lambda: webbrowser.open(SITE))
        helpmenu.add_command(label="GitHub", command=lambda: webbrowser.open(GIT_PAGE))
        helpmenu.add_command(label="Wiki", command=lambda: webbrowser.open(WIKI_PAGE))
        helpmenu.add_command(label="Report issue", command=lambda: webbrowser.open(ISSUES_PAGE))
        helpmenu.add_separator()
        helpmenu.add_command(label="About", command=lambda: self.messagebox.showinfo("About", "%s\n\n    (%s)" % (VERSION_STRING, DEV_EMAIL_ADDRESS)))
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.window.config(menu=menubar)

    def _buildHeader(self):
        self._runHover = False
        self.header = self.tk.Canvas(self.window, height=76, highlightthickness=0, borderwidth=0, background=PALETTE["base"])
        self.header.pack(fill=self.tk.X)
        self.header.bind("<Configure>", lambda e: self._drawHeader())

    def _interp(self, color1, color2, ratio):
        a = [int(color1[_:_ + 2], 16) for _ in (1, 3, 5)]
        b = [int(color2[_:_ + 2], 16) for _ in (1, 3, 5)]
        return "#%02x%02x%02x" % tuple(int(a[_] + (b[_] - a[_]) * ratio) for _ in range(3))

    def _drawHeader(self):
        p = PALETTE
        c = self.header
        c.delete("all")
        width = c.winfo_width()
        height = 76
        steps = max(1, width // 4)
        for i in range(steps):
            c.create_rectangle(i * width / steps, 0, (i + 1) * width / steps + 1, height,
                               outline="", fill=self._interp(p["blue"], p["title2"], i / float(steps)))
        c.create_text(24, 27, text="sqlmap", anchor="w", fill="#ffffff", font=self.fonts["title"])
        c.create_text(122, 31, text=VERSION_STRING.replace("sqlmap/", "v"), anchor="w", fill="#c7d8ef", font=self.fonts["subtitle"])
        c.create_text(24, 54, text="automatic SQL injection and database takeover tool", anchor="w", fill="#dfe8f6", font=self.fonts["small"])
        self._drawRunButton(width, height)

    def _drawRunButton(self, width, height):
        p = PALETTE
        c = self.header
        bw, bh = 116, 34
        x0 = width - bw - 22
        y0 = (height - bh) // 2
        x1, y1 = x0 + bw, y0 + bh
        c.create_rectangle(x0, y0, x1, y1, fill=p["base"], outline="", tags=("runbtn", "runpill"))
        # classic raised 3D bevel (white top/left, dark bottom/right)
        c.create_line(x0, y0, x1, y0, fill="#ffffff", tags="runbtn")
        c.create_line(x0, y0, x0, y1, fill="#ffffff", tags="runbtn")
        c.create_line(x0, y1, x1, y1, fill=p["dark"], tags="runbtn")
        c.create_line(x1, y0, x1, y1 + 1, fill=p["dark"], tags="runbtn")
        c.create_line(x0 + 1, y1 - 1, x1 - 1, y1 - 1, fill=p["surface1"], tags="runbtn")
        c.create_line(x1 - 1, y0 + 1, x1 - 1, y1 - 1, fill=p["surface1"], tags="runbtn")
        cy = (y0 + y1) // 2
        tx = x0 + 24
        c.create_polygon(tx, cy - 6, tx, cy + 6, tx + 10, cy, fill=p["blue"], outline="", tags=("runbtn", "runico"))
        c.create_text((x0 + x1) // 2 + 8, cy, text="Run", fill=p["text"], font=self.fonts["bodyBold"], tags=("runbtn", "runico"))
        c.tag_bind("runbtn", "<Button-1>", lambda e: self.run())
        c.tag_bind("runbtn", "<Enter>", lambda e: self._hoverRun(True))
        c.tag_bind("runbtn", "<Leave>", lambda e: self._hoverRun(False))

    def _hoverRun(self, on):
        self._runHover = on
        self.header.itemconfigure("runpill", fill="#ccccc6" if on else PALETTE["base"])
        try:
            self.header.configure(cursor="hand2" if on else "")
        except Exception:
            pass

    def _drawIcon(self, c, name, col):
        # minimal line-art icons, drawn as vectors so they render everywhere and need no assets
        c.delete("all")

        def line(*pts, **kw):
            c.create_line(*pts, fill=col, width=2, capstyle="round", joinstyle="round", **kw)

        def oval(x0, y0, x1, y1, filled=False):
            c.create_oval(x0, y0, x1, y1, outline=col, width=2, fill=(col if filled else ""))

        def rect(x0, y0, x1, y1, filled=False):
            c.create_rectangle(x0, y0, x1, y1, outline=col, width=2, fill=(col if filled else ""))

        def poly(*pts):
            c.create_polygon(*pts, fill=col, outline="")

        def arc(x0, y0, x1, y1, start, extent):
            c.create_arc(x0, y0, x1, y1, start=start, extent=extent, outline=col, width=2, style="arc")

        def dot(x, y, r=2):
            c.create_oval(x - r, y - r, x + r, y + r, fill=col, outline="")

        def glyph(text, size=11):
            c.create_text(11, 11, text=text, fill=col, font=(self.fonts["bodyBold"][0], size, "bold"))

        if name == "Quick start":
            poly(12, 3, 6, 12, 10, 12, 9, 19, 16, 9, 11, 9)
        elif name == "Target":
            oval(4, 4, 18, 18)
            dot(11, 11, 2)
        elif name == "Request":
            line(4, 8, 17, 8, arrow="last")
            line(18, 14, 5, 14, arrow="last")
        elif name == "Optimization":
            arc(4, 6, 18, 20, 0, 180)
            line(11, 13, 15, 8)
        elif name == "Injection":
            # syringe: thumb rest + plunger rod + flange + barrel + needle (no arrowhead, so it reads as a needle not a cross)
            line(9, 2, 13, 2)
            line(11, 2, 11, 5)
            line(6, 5, 16, 5)
            rect(8, 5, 14, 14)
            line(11, 14, 11, 20)
        elif name == "Detection":
            oval(4, 4, 13, 13)
            line(12, 12, 18, 18)
        elif name == "Techniques":
            oval(7, 7, 15, 15)
            line(11, 2, 11, 6)
            line(11, 16, 11, 20)
            line(2, 11, 6, 11)
            line(16, 11, 20, 11)
        elif name == "Fingerprint":
            # tightly nested tall loops with the gap at the bottom (fingertip ridges), plus a central core
            arc(3, 1, 19, 21, 285, 330)
            arc(5, 4, 17, 18, 285, 330)
            arc(7, 7, 15, 15, 285, 330)
            arc(9, 10, 13, 12, 285, 330)
        elif name == "Enumeration":
            oval(4, 3, 18, 7)
            line(4, 5, 4, 16)
            line(18, 5, 18, 16)
            arc(4, 12, 18, 18, 180, 180)
        elif name == "Brute force":
            oval(3, 7, 11, 15)
            line(9, 11, 19, 11)
            line(16, 11, 16, 15)
            line(19, 11, 19, 14)
        elif name == "User-defined function injection":
            glyph("fx", 11)
        elif name == "File system access":
            poly(3, 7, 8, 7, 10, 9, 19, 9, 19, 17, 3, 17)
        elif name == "Operating system access":
            rect(3, 5, 19, 17)
            line(6, 9, 9, 11)
            line(6, 13, 9, 13)
        elif name == "Windows registry access":
            # the waving Windows flag (4 slanted panes) rather than a plain 2x2 grid
            poly(4, 6, 10, 5, 10, 11, 4, 12)
            poly(12, 5, 18, 4, 18, 10, 12, 11)
            poly(4, 13, 10, 12, 10, 18, 4, 19)
            poly(12, 12, 18, 11, 18, 17, 12, 18)
        elif name == "General":
            line(4, 6, 18, 6)
            dot(14, 6)
            line(4, 11, 18, 11)
            dot(8, 11)
            line(4, 16, 18, 16)
            dot(13, 16)
        elif name == "Miscellaneous":
            dot(5, 11)
            dot(11, 11)
            dot(17, 11)
        else:
            dot(11, 11, 3)

    def _addPane(self, name, navText):
        p = PALETTE
        tk = self.tk
        row = tk.Frame(self.nav, background=p["mantle"])
        row.pack(fill=tk.X)
        strip = tk.Frame(row, background=p["mantle"], width=3)
        strip.pack(side=tk.LEFT, fill=tk.Y)
        icon = tk.Canvas(row, width=22, height=22, highlightthickness=0, borderwidth=0, background=p["mantle"])
        icon.pack(side=tk.LEFT, padx=(13, 0), pady=8)
        self._drawIcon(icon, name, self._iconColor(name))
        badge = tk.Label(row, text="", background=p["mantle"], foreground=p["blue"], font=self.fonts["small"])
        badge.pack(side=tk.RIGHT, padx=(0, 12))
        self.badges[name] = badge
        lab = tk.Label(row, text=navText, background=p["mantle"], foreground=p["subtext"],
                       font=self.fonts["nav"], anchor="w", padx=10, pady=9)
        lab.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for w in (row, lab, strip, icon, badge):
            w.bind("<Button-1>", lambda e, n=name: self._selectPane(n))
            w.bind("<Enter>", lambda e, n=name: self._navHover(n, True))
            w.bind("<Leave>", lambda e, n=name: self._navHover(n, False))
        self.navItems[name] = (row, strip, icon, lab, badge)
        self.paneOrder.append(name)

        outer = self.ttk.Frame(self.content, style="Card.TFrame")
        canvas = tk.Canvas(outer, background=p["base"], highlightthickness=0, borderwidth=0)
        scrollbar = self.ttk.Scrollbar(outer, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        inner = self.ttk.Frame(canvas, style="Card.TFrame", padding=(24, 20))
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.panes[name] = outer
        self.canvases[name] = canvas
        self.inners[name] = inner
        return inner

    def _iconColor(self, name):
        return PALETTE.get(ICON_COLORS.get(name, "subtext"), PALETTE["subtext"])

    def _navHover(self, name, entering):
        if name == self.currentPane:
            return
        bg = PALETTE["surface2"] if entering else PALETTE["mantle"]
        row, strip, icon, lab, badge = self.navItems[name]
        for w in (row, strip, icon, lab, badge):
            w.configure(background=bg)

    def _navKey(self, delta):
        try:
            focused = self.window.focus_get()
        except Exception:
            focused = None
        if isinstance(focused, (self.ttk.Entry, self.ttk.Combobox)):
            return None
        if self.paneOrder:
            index = self.paneOrder.index(self.currentPane)
            self._selectPane(self.paneOrder[(index + delta) % len(self.paneOrder)])
        return "break"

    def _selectPane(self, name):
        if name not in self.built:                       # lazy: populate the pane on first visit
            self.builders[name](self.inners[name])
            self.built.add(name)
        if self.currentPane == name:
            return
        p = PALETTE
        if self.currentPane:
            self.panes[self.currentPane].pack_forget()
            row, strip, icon, lab, badge = self.navItems[self.currentPane]
            for w in (row, strip, icon):
                w.configure(background=p["mantle"])
            lab.configure(background=p["mantle"], foreground=p["text"], font=self.fonts["nav"])
            badge.configure(background=p["mantle"], foreground=p["blue"])
            self._drawIcon(icon, self.currentPane, self._iconColor(self.currentPane))
        self.panes[name].pack(expand=True, fill=self.tk.BOTH)
        row, strip, icon, lab, badge = self.navItems[name]
        for w in (row, strip, icon):
            w.configure(background=p["blue"])
        lab.configure(background=p["blue"], foreground="#ffffff", font=self.fonts["bodyBold"])
        badge.configure(background=p["blue"], foreground="#ffffff")
        self._drawIcon(icon, name, "#ffffff")
        self.currentPane = name
        self._ensureNavVisible(name)

        if hasattr(self, "hint"):        # don't leave the previous section's option hint lingering
            self.hint.set(HINT_DEFAULT)

    def _ensureNavVisible(self, name):
        # scroll the sidebar so the active item stays in view (e.g. when paging with Up/Down)
        try:
            row = self.navItems[name][0]
            self.nav.update_idletasks()
            total = self.nav.winfo_height()
            viewH = self.navCanvas.winfo_height()
            if total <= 1 or viewH <= 1:
                return
            top = row.winfo_y()
            bottom = top + row.winfo_height()
            curTop = self.navCanvas.yview()[0] * total
            if top < curTop:
                self.navCanvas.yview_moveto(float(top) / total)
            elif bottom > curTop + viewH:
                self.navCanvas.yview_moveto(float(bottom - viewH) / total)
        except Exception:
            pass

    def _onWheel(self, event):
        # route the wheel to whichever scroll region the pointer is over (sidebar or content)
        delta = 1 if getattr(event, "num", None) == 5 or getattr(event, "delta", 0) < 0 else -1
        target = None
        node = self.window.winfo_containing(event.x_root, event.y_root)
        while node is not None:
            if node is self.navCanvas:
                target = self.navCanvas
                break
            if self.currentPane and node is self.canvases.get(self.currentPane):
                target = self.canvases[self.currentPane]
                break
            try:
                node = node.master
            except Exception:
                break
        if target is None and self.currentPane:
            target = self.canvases.get(self.currentPane)
        if target is not None:
            target.yview_scroll(delta, "units")
        return "break"

    def _buildQuickStartPane(self):
        name = "Quick start"
        self._addPane(name, name)
        self.sectionDests[name] = [_ for _ in QUICK_START_DESTS if _ in self.optionByDest]

        def build(inner):
            self.ttk.Label(inner, text="Quick start", style="Pane.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            self.ttk.Label(inner, text="The options people reach for most. Set the target above, tick what you want, then Run.",
                           style="Desc.TLabel", wraplength=640, justify="left").grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 14))
            row = 2
            for dest in QUICK_START_DESTS:
                option = self.optionByDest.get(dest)
                if option is not None:
                    row = self._buildFieldRow(inner, option, row)
            inner.columnconfigure(1, weight=1)

        self.builders[name] = build

    def _buildGroupPane(self, group):
        title = _groupTitle(group)
        self._addPane(title, NAV_ALIASES.get(title, title))
        self.sectionDests[title] = [_optDest(_) for _ in _groupOptions(group) if _optDest(_)]

        def build(inner, group=group, title=title):
            self.ttk.Label(inner, text=title, style="Pane.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            row = 1
            description = _groupDescription(group)
            if description:
                self.ttk.Label(inner, text=description, style="Desc.TLabel", wraplength=640, justify="left").grid(
                    row=row, column=0, columnspan=2, sticky="w", pady=(2, 14))
                row += 1
            for option in _groupOptions(group):
                row = self._buildFieldRow(inner, option, row)
            inner.columnconfigure(1, weight=1)

        self.builders[title] = build

    def _destVar(self, dest, is_bool):
        # one shared variable per option, so every widget that edits it (Quick start pane,
        # the proper group pane, the target bar) reflects into the same value both ways
        if dest not in self.vars:
            self.vars[dest] = self.tk.IntVar() if is_bool else self.tk.StringVar()
        return self.vars[dest]

    def _buildFieldRow(self, parent, option, row):
        p = PALETTE
        tk = self.tk
        label = _optionLabel(option)
        helptext = _optHelp(option)
        dest = _optDest(option)
        is_bool = not _optTakesValue(option)
        firstSeen = dest not in self.vars

        def bindHint(widget):
            widget.bind("<Enter>", lambda e: self.hint.set(helptext), add="+")
            widget.bind("<FocusIn>", lambda e: self.hint.set(helptext), add="+")
            widget.bind("<Leave>", lambda e: self.hint.set(HINT_DEFAULT), add="+")
            widget.bind("<FocusOut>", lambda e: self.hint.set(HINT_DEFAULT), add="+")

        if is_bool:
            var = self._destVar(dest, True)
            chk = self.ttk.Checkbutton(parent, text=label, variable=var, takefocus=True)
            chk.grid(row=row, column=0, columnspan=2, sticky="w", pady=5)
            _Tooltip(chk, helptext, tk, p)
            bindHint(chk)
            if firstSeen:
                self.widgets[dest] = ("bool", var)
        else:
            otype = _optValueType(option)
            var = self._destVar(dest, False)
            if firstSeen:
                default = defaults.get(dest)
                if default not in (None, False):
                    var.set(default)
                self.widgets[dest] = (otype, var)
            lab = self.ttk.Label(parent, text=label, style="Field.TLabel")
            lab.grid(row=row, column=0, sticky="w", padx=(0, 18), pady=6)
            _Tooltip(lab, helptext, tk, p)
            bindHint(lab)
            choices = _optChoices(option)
            if choices:
                widget = self.ttk.Combobox(parent, values=list(choices), state="readonly", textvariable=var)
            else:
                widget = self.ttk.Entry(parent, textvariable=var)
                if otype in ("int", "float"):
                    self._constrain(widget, otype)
            widget.grid(row=row, column=1, sticky="ew", pady=6)
            _Tooltip(widget, helptext, tk, p)
            bindHint(widget)
        return row + 1

    def _constrain(self, entry, otype):
        check = (lambda s: s == "" or s.replace(".", "", 1).isdigit()) if otype == "float" else (lambda s: s == "" or s.isdigit())
        vcmd = (self.window.register(lambda proposed: bool(check(proposed))), "%P")
        entry.configure(validate="key", validatecommand=vcmd)

    # --- helpers --------------------------------------------------------

    def _center(self, window, width=None, height=None):
        window.update_idletasks()
        width = width or window.winfo_width()
        height = height or window.winfo_height()
        x = window.winfo_screenwidth() // 2 - width // 2
        y = window.winfo_screenheight() // 2 - height // 2
        window.geometry("%dx%d+%d+%d" % (width, height, x, y))

    def _updateStats(self):
        setDests = set()
        for dest, (otype, var) in self.widgets.items():
            try:
                if otype == "bool":
                    if var.get():
                        setDests.add(dest)
                else:
                    raw = var.get()
                    if raw not in (None, "") and str(raw) != str(defaults.get(dest, "")):
                        setDests.add(dest)
            except Exception:
                pass
        count = len(setDests)
        self.stat.set("%d option%s set" % (count, "" if count == 1 else "s"))
        for name, dests in self.sectionDests.items():
            badge = self.badges.get(name)
            if badge is not None:
                hits = sum(1 for _ in dests if _ in setDests)
                badge.configure(text=(str(hits) if hits else ""))

    def _buildCommandString(self):
        parts = ["sqlmap.py"]
        for dest, (otype, var) in self.widgets.items():
            option = self.optionByDest.get(dest)
            if option is None:
                continue
            strings = _optStrings(option)
            if not strings:
                continue
            flag = strings[0]
            try:
                if otype == "bool":
                    if var.get():
                        parts.append(flag)
                else:
                    raw = var.get()
                    if raw not in (None, "") and str(raw) != str(defaults.get(dest, "")):
                        value = str(raw)
                        if " " in value or '"' in value:
                            value = '"%s"' % value.replace('"', '\\"')
                        parts.append("%s %s" % (flag, value))
            except Exception:
                pass
        return " ".join(parts)

    def _tickStats(self):
        self._updateStats()
        self.command.set(self._buildCommandString())
        self.window.after(1200, self._tickStats)

    def _copyCommand(self):
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(self.command.get())
            self.hint.set("Command copied to clipboard")
        except Exception:
            pass

    def _focusTarget(self):
        try:
            self.targetEntry.focus_set()
            self.targetEntry.select_range(0, "end")
        except Exception:
            pass
        return "break"

    def _collectConfig(self):
        config = {}
        for dest, (otype, var) in self.widgets.items():
            try:
                if otype == "bool":
                    value = bool(var.get())
                else:
                    raw = var.get()
                    if raw in (None, ""):
                        value = None
                    elif otype == "int":
                        value = int(raw)
                    elif otype == "float":
                        value = float(raw)
                    else:
                        value = raw
            except Exception:
                value = None
            config[dest] = value
        for option in self.optionByDest.values():
            dest = _optDest(option)
            if config.get(dest) is None:
                config[dest] = defaults.get(dest, None)
        return config

    def _setWidgetValue(self, dest, value):
        if dest not in self.widgets:
            return
        otype, var = self.widgets[dest]
        try:
            if otype == "bool":
                var.set(1 if value else 0)
            else:
                var.set("" if value in (None, False) else value)
        except Exception:
            pass

    # --- actions --------------------------------------------------------

    def loadConfig(self):
        path = self.filedialog.askopenfilename(title="Load configuration", filetypes=[("sqlmap config", "*.conf *.ini"), ("All files", "*.*")])
        if not path:
            return
        try:
            from thirdparty.six.moves import configparser as _configparser
            parser = _configparser.ConfigParser()
            parser.read(path)
            count = 0
            for section in parser.sections():
                for name, value in parser.items(section):
                    if name in self.widgets:
                        if self.widgets[name][0] == "bool":
                            self._setWidgetValue(name, str(value).lower() in ("1", "true", "yes", "on"))
                        else:
                            self._setWidgetValue(name, value)
                        count += 1
            self.hint.set("Loaded %d options from %s" % (count, os.path.basename(path)))
        except Exception as ex:
            self.messagebox.showerror("Load failed", getSafeExString(ex))

    def saveConfigDialog(self):
        path = self.filedialog.asksaveasfilename(title="Save configuration", defaultextension=".conf", filetypes=[("sqlmap config", "*.conf")])
        if not path:
            return
        try:
            saveConfig(self._collectConfig(), path)
            self.hint.set("Saved configuration to %s" % os.path.basename(path))
        except Exception as ex:
            self.messagebox.showerror("Save failed", getSafeExString(ex))

    def run(self):
        config = self._collectConfig()
        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
        os.close(handle)
        saveConfig(config, configFile)

        self.alive = True
        self.process = subprocess.Popen([sys.executable or "python", os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap.py"), "-c", configFile],
                                        shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
                                        bufsize=1, close_fds=not IS_WIN)
        self.queue = _queue.Queue()

        def enqueue(stream, queue):
            for line in iter(stream.readline, b''):
                queue.put(line)
            self.alive = False
            stream.close()

        thread = threading.Thread(target=enqueue, args=(self.process.stdout, self.queue))
        thread.daemon = True
        thread.start()
        self._openConsole()

    def _openConsole(self):
        p = PALETTE
        tk = self.tk
        top = tk.Toplevel(self.window)
        top.title("sqlmap - console")
        top.configure(background=p["crust"])
        frame = self.ttk.Frame(top, style="Card.TFrame", padding=10)
        frame.configure(style="Card.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)

        text = self.scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg=p["crust"], fg=p["text"],
                                              insertbackground=p["blue"], relief="flat", borderwidth=0,
                                              font=self.fonts["mono"], padx=12, pady=10)
        text.pack(fill=tk.BOTH, expand=True)
        text.focus()
        lineBuffer = {"value": ""}

        def onKey(event):
            if self.process:
                if event.char == "\b":
                    lineBuffer["value"] = lineBuffer["value"][:-1]
                elif event.char:
                    lineBuffer["value"] += event.char

        def onReturn(event):
            if self.process:
                try:
                    self.process.stdin.write(("%s\n" % lineBuffer["value"].strip()).encode())
                    self.process.stdin.flush()
                except Exception:
                    pass
                lineBuffer["value"] = ""
                text.insert(tk.END, "\n")
                return "break"

        text.bind("<Key>", onKey)
        text.bind("<Return>", onReturn)

        def pump():
            drained = False
            try:
                while True:
                    line = self.queue.get_nowait()
                    text.insert(tk.END, line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line)
                    drained = True
            except _queue.Empty:
                pass
            if drained:
                text.see(tk.END)
            if self.alive or not self.queue.empty():
                top.after(80, pump)
            else:
                text.insert(tk.END, "\n--- process finished ---\n")
                text.see(tk.END)

        self._center(top, 900, 580)
        top.after(80, pump)

def runGui(parser):
    try:
        from thirdparty.six.moves import tkinter as _tkinter
        from thirdparty.six.moves import tkinter_scrolledtext as _scrolledtext
        from thirdparty.six.moves import tkinter_ttk as _ttk
        from thirdparty.six.moves import tkinter_messagebox as _messagebox
        from thirdparty.six.moves import tkinter_filedialog as _filedialog
        from thirdparty.six.moves import tkinter_font as _font
    except ImportError as ex:
        raise SqlmapMissingDependence("missing dependence ('%s')" % getSafeExString(ex))

    app = SqlmapGui(parser, _tkinter, _ttk, _scrolledtext, _messagebox, _filedialog, _font)
    app.window.mainloop()
