#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import io
import os
import subprocess
import sys
import tempfile
import threading
import time
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

try:
    _text_type = unicode
except NameError:
    _text_type = str

_binary_type = str if sys.version_info[0] < 3 else bytes
_clock = getattr(time, "perf_counter", getattr(time, "clock", time.time))

def _toText(value):
    """Return a Unicode text value on both Python 2.7 and Python 3.x."""
    if value is None:
        return u""
    if isinstance(value, _text_type):
        return value
    if isinstance(value, _binary_type):
        try:
            return value.decode("utf-8", "replace")
        except Exception:
            return _text_type(value)
    try:
        return _text_type(value)
    except Exception:
        return _text_type(repr(value))

def _toBytes(value):
    """Return UTF-8 bytes suitable for a binary subprocess pipe."""
    if isinstance(value, _binary_type):
        return value
    return _toText(value).encode("utf-8", "replace")

def _waitForProcess(process, timeout):
    """Python 2 compatible replacement for Popen.wait(timeout=...)."""
    deadline = _clock() + max(0.0, timeout)
    while process.poll() is None and _clock() < deadline:
        time.sleep(0.03)
    return process.poll()

def _list2cmdline(arguments):
    values = [_toText(_) for _ in arguments]
    if sys.version_info[0] < 3:
        return _toText(subprocess.list2cmdline([_toBytes(_) for _ in values]))
    return _toText(subprocess.list2cmdline(values))

# A restrained security-tool palette: the layout stays familiar, while the darker
# navigation, cyan accents and terminal surfaces add a light Havij-era character.
PALETTE = {
    "base": "#d7dce1",
    "mantle": "#243545",
    "crust": "#101820",
    "surface0": "#f8fafb",
    "surface1": "#8d98a3",
    "surface2": "#e7ebef",
    "light": "#ffffff",
    "dark": "#3c4650",
    "text": "#17212b",
    "subtext": "#33414f",
    "overlay": "#657381",
    "title2": "#0b79a5",
    "blue": "#164d73",
    "sapphire": "#087caf",
    "sky": "#169ec1",
    "green": "#2d9659",
    "teal": "#178b86",
    "red": "#bd3f45",
    "maroon": "#8c3d56",
    "mauve": "#86549a",
    "pink": "#b34e83",
    "peach": "#c56d35",
    "yellow": "#b78a18",
    "lavender": "#6172b8",
    "flamingo": "#bf5b72",
    "gold": "#d29b22",
    "navText": "#eef4f8",
    "navMuted": "#a9bac8",
    "navHover": "#31485d",
    "panel": "#eef2f5",
    "border": "#9ca7b1",
    "success": "#2f9b5b",
    "command": "#13232e",
    "commandText": "#8de19b",
    "consoleText": "#d8e7de",
    "consoleMuted": "#8fa69a",
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
MAX_CONSOLE_LINES = 12000
MAX_SEARCH_RESULTS = 12

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

def _preferredFlag(option):
    strings = _optStrings(option)
    longOptions = [_ for _ in strings if _.startswith("--")]
    return (longOptions or strings or [""])[0]

def _quoteArg(value):
    value = _toText(value)
    if IS_WIN:
        return _list2cmdline([value])
    if not value:
        return u"''"
    safe = u"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
    if all(character in safe for character in value):
        return value
    return u"'" + value.replace(u"'", u"'\"'\"'") + u"'"

class _TooltipManager(object):
    """One shared tooltip/hint dispatcher for every option control.

    Per-widget Python/Tcl bindings are surprisingly expensive when a pane contains
    dozens of options. Widgets only receive a small Python attribute; four global
    bindings handle the whole application.
    """

    def __init__(self, owner, root, tk, palette, delay=500):
        self._owner = owner
        self._root = root
        self._tk = tk
        self._palette = palette
        self._delay = delay
        self._widget = None
        self._tip = None
        self._job = None
        root.bind_all("<Enter>", self._enter, add="+")
        root.bind_all("<Leave>", self._leave, add="+")
        root.bind_all("<FocusIn>", self._focusIn, add="+")
        root.bind_all("<FocusOut>", self._focusOut, add="+")
        root.bind_all("<ButtonPress>", self._hide, add="+")

    def attach(self, widget, text):
        if text:
            widget._sqlmap_help = text

    def _textFor(self, widget):
        return getattr(widget, "_sqlmap_help", "")

    def _setHint(self, text):
        try:
            if hasattr(self._owner, "hint"):
                self._owner.hint.set(text or HINT_DEFAULT)
        except Exception:
            pass

    def _enter(self, event):
        text = self._textFor(event.widget)
        if not text:
            return
        self._widget = event.widget
        self._setHint(text)
        self._cancel()
        try:
            self._job = self._root.after(self._delay, self._show)
        except Exception:
            self._job = None

    def _leave(self, event):
        if event.widget is self._widget:
            self._widget = None
            self._cancel()
            self._hide()
            self._setHint(HINT_DEFAULT)

    def _focusIn(self, event):
        text = self._textFor(event.widget)
        if text:
            self._setHint(text)

    def _focusOut(self, event):
        if self._textFor(event.widget):
            self._setHint(HINT_DEFAULT)

    def _cancel(self):
        if self._job is not None:
            try:
                self._root.after_cancel(self._job)
            except Exception:
                pass
            self._job = None

    def _show(self):
        self._job = None
        widget = self._widget
        text = self._textFor(widget) if widget is not None else ""
        if not text:
            return
        try:
            if not widget.winfo_exists():
                return
            x = widget.winfo_rootx() + 18
            y = widget.winfo_rooty() + widget.winfo_height() + 6
            self._tip = tw = self._tk.Toplevel(widget)
            # Toplevels are initially mapped by Tk at the default 0,0 position.
            # Keep the tooltip withdrawn until its children have been measured and
            # its final geometry has been assigned; otherwise X11 briefly paints an
            # empty box in the screen corner before the real tooltip appears.
            tw.withdraw()
            tw.wm_overrideredirect(True)
            try:
                tw.wm_transient(self._root)
            except Exception:
                pass
            self._tk.Label(tw, text=text, justify="left", background=self._palette["surface0"],
                           foreground=self._palette["text"], relief="solid", borderwidth=1,
                           wraplength=460, padx=10, pady=7).pack()
            tw.update_idletasks()
            width = max(1, tw.winfo_reqwidth())
            height = max(1, tw.winfo_reqheight())
            x = min(x, max(0, tw.winfo_screenwidth() - width - 8))
            y = min(y, max(0, tw.winfo_screenheight() - height - 8))
            tw.wm_geometry("%dx%d+%d+%d" % (width, height, x, y))
            tw.deiconify()
            tw.lift()
        except Exception:
            if self._tip is not None:
                try:
                    self._tip.destroy()
                except Exception:
                    pass
            self._tip = None

    def _hide(self, event=None):
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
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

        self.widgets = {}                # dest -> (type, shared effective-value Tk variable)
        self.vars = {}                   # dest -> shared Tk variable (one per option)
        self.optionByDest = {}
        self.optionOrder = []
        self.sectionByDest = {}
        self.searchIndex = []
        for group in _parserGroups(parser):
            title = _groupTitle(group)
            for option in _groupOptions(group):
                dest = _optDest(option)
                if dest:
                    if dest not in self.optionByDest:
                        self.optionOrder.append(dest)
                    self.optionByDest[dest] = option
                    self.sectionByDest[dest] = title

        for index, dest in enumerate(self.optionOrder):
            option = self.optionByDest[dest]
            section = self.sectionByDest.get(dest, "")
            label = _optionLabel(option)
            flag = _preferredFlag(option)
            self.searchIndex.append((
                dest,
                index,
                label,
                section,
                flag,
                " ".join((label, dest, section, _optHelp(option))).lower(),
            ))

        self.panes = {}                  # name -> outer frame
        self.navItems = {}               # name -> (row frame, accent strip, icon canvas, label, badge)
        self.canvases = {}               # name -> canvas (for wheel binding)
        self.inners = {}                 # name -> scrollable inner frame (populated lazily)
        self.builders = {}               # name -> callable that populates the inner frame
        self.built = set()               # names whose content has been built
        self.buildStates = {}            # name -> generator for incremental pane construction
        self._prebuildQueue = []
        self._prebuildJob = None
        self.badges = {}                 # name -> sidebar count badge label
        self.sectionDests = {}           # name -> [option dests in that section]
        self.paneOrder = []              # nav order, for Up/Down navigation
        self.currentPane = None
        self.controlsByDest = {}          # dest -> [(pane name, interactive widget)]
        self.searchMatches = []

        self.process = None
        self.processQueue = None
        self.processConfigFile = None
        self.consoleWindow = None
        self.consoleText = None
        self.consoleStatus = None
        self._runSerial = 0
        self._refreshJob = None
        self._searchJob = None
        self._headerJob = None
        self._suspendRefresh = False

        try:
            self.window = tk.Tk()
        except Exception as ex:
            raise SqlmapSystemException("unable to create GUI window ('%s')" % getSafeExString(ex))

        self.tooltip = _TooltipManager(self, self.window, tk, PALETTE)
        self._initializeVariables()
        self._initFonts()
        self._initStyle()
        self._buildLayout()
        self.window.protocol("WM_DELETE_WINDOW", self._closeApplication)

    def _initializeVariables(self):
        for dest in self.optionOrder:
            option = self.optionByDest[dest]
            isBool = not _optTakesValue(option)
            otype = "bool" if isBool else _optValueType(option)
            default = defaults.get(dest)
            if isBool:
                var = self.tk.BooleanVar(value=bool(default))
            else:
                var = self.tk.StringVar(value="" if default in (None, False) else default)
            self.vars[dest] = var
            self.widgets[dest] = (otype, var)
            try:
                var.trace("w", self._onOptionChanged)
            except Exception:
                pass

    def _onOptionChanged(self, *unused):
        if not self._suspendRefresh:
            self._scheduleRefresh()

    def _scheduleRefresh(self, delay=70):
        if self._refreshJob is not None:
            try:
                self.window.after_cancel(self._refreshJob)
            except Exception:
                pass
        self._refreshJob = self.window.after(delay, self._refreshDerivedState)

    def _refreshDerivedState(self):
        self._refreshJob = None
        self._updateStats()
        self.command.set(self._buildCommandString())
        self._updateStatusLight()

    def _updateStatusLight(self):
        try:
            canvas = self.statusLight
        except AttributeError:
            return
        try:
            canvas.delete("all")
            if self._isRunning():
                color = PALETTE["success"]
            elif any(self._isOptionSet(_) for _ in self.widgets):
                color = PALETTE["sky"]
            else:
                color = PALETTE["surface1"]
            canvas.create_oval(2, 2, 10, 10, fill=color, outline=PALETTE["dark"])
        except Exception:
            pass


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
        face = p["base"]
        field = p["surface0"]
        style = self.ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=face, foreground=p["text"], fieldbackground=field,
                        bordercolor=p["border"], lightcolor=p["light"], darkcolor=p["surface1"],
                        troughcolor=p["surface2"], focuscolor=p["blue"], insertcolor=p["text"],
                        font=self.fonts["body"])

        style.configure("TFrame", background=face)
        style.configure("Bar.TFrame", background=p["panel"])
        style.configure("Nav.TFrame", background=p["mantle"])
        style.configure("Card.TFrame", background=p["panel"])
        style.configure("Panel.TFrame", background=p["surface0"])
        style.configure("PaneHeader.TFrame", background=p["surface0"])

        style.configure("TLabel", background=face, foreground=p["text"])
        style.configure("Title.TLabel", background=p["blue"], foreground="#ffffff", font=self.fonts["title"])
        style.configure("Subtitle.TLabel", background=p["blue"], foreground="#dceaf2", font=self.fonts["subtitle"])
        style.configure("Hint.TLabel", background=p["panel"], foreground=p["overlay"], font=self.fonts["small"])
        style.configure("PanelHint.TLabel", background=p["surface0"], foreground=p["overlay"], font=self.fonts["small"])
        style.configure("PanelLabel.TLabel", background=p["surface0"], foreground=p["blue"], font=self.fonts["bodyBold"])
        style.configure("NavHint.TLabel", background=p["mantle"], foreground=p["navMuted"], font=self.fonts["small"])
        style.configure("NavTitle.TLabel", background=p["mantle"], foreground=p["navText"], font=self.fonts["bodyBold"])
        style.configure("Field.TLabel", background=p["panel"], foreground=p["text"])
        style.configure("Desc.TLabel", background=p["panel"], foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Pane.TLabel", background=p["surface0"], foreground=p["blue"], font=self.fonts["title"])
        style.configure("PaneCount.TLabel", background=p["surface0"], foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Stat.TLabel", background=p["panel"], foreground=p["overlay"], font=self.fonts["small"])
        style.configure("Prompt.TLabel", background=field, foreground=p["text"], font=self.fonts["mono"])

        style.configure("TButton", background=p["surface2"], foreground=p["text"], relief="raised", borderwidth=1,
                        lightcolor=p["light"], darkcolor=p["surface1"], bordercolor=p["border"],
                        focuscolor=p["blue"], padding=(11, 5))
        style.map("TButton", background=[("active", p["surface0"]), ("pressed", p["surface1"])],
                  relief=[("pressed", "sunken")])
        style.configure("Tool.TButton", padding=(9, 4), font=self.fonts["small"])
        style.configure("Primary.TButton", background=p["success"], foreground="#ffffff", bordercolor=p["green"],
                        lightcolor="#78c89a", darkcolor="#17643a", padding=(12, 5), font=self.fonts["bodyBold"])
        style.map("Primary.TButton", background=[("active", "#39aa68"), ("pressed", "#247c49")],
                  foreground=[("disabled", "#d7e4dc")])

        style.configure("TEntry", fieldbackground=field, foreground=p["text"], relief="sunken", borderwidth=1,
                        bordercolor=p["border"], lightcolor=p["surface1"], darkcolor=p["light"],
                        insertcolor=p["text"], padding=5)
        style.configure("Target.TEntry", fieldbackground="#ffffff", foreground=p["text"], relief="sunken", borderwidth=1,
                        bordercolor=p["sapphire"], lightcolor=p["surface1"], darkcolor=p["light"],
                        insertcolor=p["text"], padding=7, font=self.fonts["body"])
        style.configure("Search.TEntry", fieldbackground="#192936", foreground=p["navText"], relief="flat", borderwidth=1,
                        bordercolor="#4c6376", lightcolor="#4c6376", darkcolor="#17242f",
                        insertcolor="#ffffff", padding=6)

        style.configure("TCheckbutton", background=p["panel"], foreground=p["text"], focuscolor=p["panel"], padding=2,
                        indicatorbackground=field, indicatorforeground=p["blue"], indicatorrelief="sunken",
                        indicatorborderwidth=1, bordercolor=p["border"], lightcolor=p["surface1"], darkcolor=p["light"])
        style.map("TCheckbutton", background=[("active", p["panel"])],
                  indicatorbackground=[("active", field), ("selected", field)])

        style.configure("TCombobox", fieldbackground=field, background=p["surface2"], foreground=p["text"],
                        arrowcolor=p["blue"], relief="sunken", borderwidth=1, bordercolor=p["border"],
                        lightcolor=p["surface1"], darkcolor=p["light"], padding=4)

        style.configure("Vertical.TScrollbar", background=p["surface2"], troughcolor=p["panel"],
                        bordercolor=p["border"], lightcolor=p["light"], darkcolor=p["surface1"],
                        arrowcolor=p["text"], relief="raised", width=16)
        style.map("Vertical.TScrollbar", background=[("active", p["surface0"])])

        self.window.configure(background=face)

    def _buildLayout(self):
        tk = self.tk
        p = PALETTE
        self.window.title("sqlmap GUI")
        self.window.minsize(980, 690)
        self._buildMenu()
        self._buildHeader()

        targetShell = tk.Frame(self.window, background=p["border"], borderwidth=0)
        targetShell.pack(fill=tk.X, padx=16, pady=(10, 8))
        target = self.ttk.Frame(targetShell, style="Panel.TFrame", padding=(14, 10, 14, 12))
        target.pack(fill=tk.X, padx=1, pady=1)
        tk.Frame(target, background=p["red"], height=3).pack(fill=tk.X, pady=(0, 9))

        labelRow = self.ttk.Frame(target, style="Panel.TFrame")
        labelRow.pack(fill=tk.X, pady=(0, 5))
        self.ttk.Label(labelRow, text="TARGET URL", style="PanelLabel.TLabel").pack(side=tk.LEFT)
        self.ttk.Label(labelRow, text="Ctrl+L", style="PanelHint.TLabel").pack(side=tk.RIGHT)
        self.ttk.Label(labelRow, text="  e.g. %s" % TARGET_PLACEHOLDER, style="PanelHint.TLabel").pack(side=tk.LEFT)

        targetRow = self.ttk.Frame(target, style="Panel.TFrame")
        targetRow.pack(fill=tk.X)
        urlVar = self._destVar("url", False)
        self.targetEntry = self.ttk.Entry(targetRow, style="Target.TEntry", textvariable=urlVar)
        self.targetEntry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=1)
        self.ttk.Button(targetRow, text="Paste", style="Tool.TButton", command=self._pasteTarget,
                        takefocus=False).pack(side=tk.LEFT, padx=(8, 0))
        self.ttk.Button(targetRow, text="Clear", style="Tool.TButton", command=self._clearTarget,
                        takefocus=False).pack(side=tk.LEFT, padx=(6, 0))
        self.controlsByDest.setdefault("url", []).append((None, self.targetEntry))

        body = self.ttk.Frame(self.window, style="TFrame")
        body.pack(expand=True, fill=tk.BOTH)

        navHolder = self.ttk.Frame(body, style="Nav.TFrame", width=224)
        navHolder.pack(side=tk.LEFT, fill=tk.Y)
        navHolder.pack_propagate(False)

        searchBar = self.ttk.Frame(navHolder, style="Nav.TFrame", padding=(11, 11, 11, 8))
        searchBar.pack(fill=tk.X)
        searchTitle = self.ttk.Frame(searchBar, style="Nav.TFrame")
        searchTitle.pack(fill=tk.X, pady=(0, 5))
        self.ttk.Label(searchTitle, text="OPTION FINDER", style="NavTitle.TLabel").pack(side=tk.LEFT)
        self.ttk.Label(searchTitle, text="Ctrl+K", style="NavHint.TLabel").pack(side=tk.RIGHT)
        self.searchVar = tk.StringVar(value="")
        self.searchEntry = self.ttk.Entry(searchBar, style="Search.TEntry", textvariable=self.searchVar)
        self.searchEntry.pack(fill=tk.X)
        self.searchEntry.bind("<Return>", self._activateSearchResult)
        self.searchEntry.bind("<Down>", self._searchMoveDown)
        try:
            self.searchVar.trace("w", self._scheduleSearch)
        except Exception:
            pass

        self.searchList = tk.Listbox(navHolder, height=6, activestyle="dotbox", exportselection=False,
                                     bg="#192936", fg=p["navText"], selectbackground=p["sapphire"],
                                     selectforeground="#ffffff", relief="flat", borderwidth=1,
                                     highlightthickness=1, highlightbackground="#4c6376",
                                     font=self.fonts["small"])
        self.searchList.bind("<ButtonRelease-1>", self._clickSearchResult)
        self.searchList.bind("<Return>", self._activateSearchResult)

        self.navCanvas = tk.Canvas(navHolder, background=p["mantle"], highlightthickness=0, borderwidth=0)
        navScroll = self.ttk.Scrollbar(navHolder, orient="vertical", command=self.navCanvas.yview,
                                       style="Vertical.TScrollbar")
        self.nav = self.ttk.Frame(self.navCanvas, style="Nav.TFrame")
        self.nav.bind("<Configure>", lambda e: self.navCanvas.configure(scrollregion=self.navCanvas.bbox("all")))
        navWin = self.navCanvas.create_window((0, 0), window=self.nav, anchor="nw")
        self.navCanvas.bind("<Configure>", lambda e: self.navCanvas.itemconfigure(navWin, width=e.width))
        self.navCanvas.configure(yscrollcommand=navScroll.set)
        self.navCanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        navScroll.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Frame(body, background=p["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        self.content = self.ttk.Frame(body, style="Card.TFrame")
        self.content.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        cmdBar = self.ttk.Frame(self.window, style="Bar.TFrame", padding=(16, 8))
        cmdBar.pack(fill=tk.X)
        self.ttk.Label(cmdBar, text=">_", style="PanelLabel.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        self.ttk.Button(cmdBar, text="Copy", style="Tool.TButton", command=self._copyCommand,
                        takefocus=False).pack(side=tk.RIGHT, padx=(7, 0))
        self.ttk.Button(cmdBar, text="Reset", style="Tool.TButton", command=self.resetOptions,
                        takefocus=False).pack(side=tk.RIGHT, padx=(7, 0))
        self.command = tk.StringVar(value="sqlmap.py")
        cmdEntry = tk.Entry(cmdBar, textvariable=self.command, font=self.fonts["mono"],
                            bg=p["command"], fg=p["commandText"], readonlybackground=p["command"],
                            disabledforeground=p["commandText"], relief="flat", borderwidth=0,
                            highlightthickness=1, highlightbackground=p["border"],
                            highlightcolor=p["sapphire"], state="readonly")
        cmdEntry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        hintBar = self.ttk.Frame(self.window, style="Bar.TFrame", padding=(16, 8))
        hintBar.pack(fill=tk.X)
        self.statusLight = tk.Canvas(hintBar, width=12, height=12, background=p["panel"],
                                     highlightthickness=0, borderwidth=0)
        self.statusLight.pack(side=tk.LEFT, padx=(0, 8))
        self.stat = tk.StringVar(value="")
        self.ttk.Label(hintBar, textvariable=self.stat, style="Stat.TLabel", anchor="e").pack(side=tk.RIGHT, padx=(12, 0))
        self.hint = tk.StringVar(value=HINT_DEFAULT)
        self.ttk.Label(hintBar, textvariable=self.hint, style="Hint.TLabel", anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._buildQuickStartPane()
        for group in _parserGroups(self.parser):
            self._buildGroupPane(group)

        self._prebuildQueue = list(self.paneOrder)
        self._selectPane("Quick start")
        self.window.bind("<Down>", lambda e: self._navKey(1))
        self.window.bind("<Up>", lambda e: self._navKey(-1))
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.window.bind_all(seq, self._onWheel)
        self.window.bind("<F5>", lambda e: self.run())
        self.window.bind("<Control-r>", lambda e: self.run())
        self.window.bind("<Control-Return>", lambda e: self.run())
        self.window.bind("<Control-l>", lambda e: self._focusTarget())
        self.window.bind("<Control-k>", lambda e: self._focusSearch())
        self.window.bind("<Escape>", self._escapeAction)
        self.window.bind("<Control-s>", lambda e: self.saveConfigDialog())
        self.window.bind("<Control-o>", lambda e: self.loadConfig())
        self._enableSelectAll()
        self._refreshDerivedState()
        self._center(self.window, 1060, 750)
        self._schedulePanePrebuild(60)

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
        menuKw = dict(bg=p["panel"], fg=p["text"], activebackground=p["sapphire"],
                      activeforeground="#ffffff")
        menubar = self.tk.Menu(self.window, borderwidth=0, **menuKw)
        filemenu = self.tk.Menu(menubar, tearoff=0, **menuKw)
        filemenu.add_command(label="Load configuration...", command=self.loadConfig)
        filemenu.add_command(label="Save configuration...", command=self.saveConfigDialog)
        filemenu.add_command(label="Reset all options", command=self.resetOptions)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self._closeApplication)
        menubar.add_cascade(label="File", menu=filemenu)
        menubar.add_command(label="Run", command=self.run)
        helpmenu = self.tk.Menu(menubar, tearoff=0, **menuKw)
        helpmenu.add_command(label="Official site", command=lambda: webbrowser.open(SITE))
        helpmenu.add_command(label="GitHub", command=lambda: webbrowser.open(GIT_PAGE))
        helpmenu.add_command(label="Wiki", command=lambda: webbrowser.open(WIKI_PAGE))
        helpmenu.add_command(label="Report issue", command=lambda: webbrowser.open(ISSUES_PAGE))
        helpmenu.add_separator()
        helpmenu.add_command(label="About", command=lambda: self.messagebox.showinfo(
            "About", "%s\n\n    (%s)" % (VERSION_STRING, DEV_EMAIL_ADDRESS)))
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.window.config(menu=menubar)

    def _buildHeader(self):
        self._runHover = False
        self.header = self.tk.Canvas(self.window, height=76, highlightthickness=0, borderwidth=0, background=PALETTE["base"])
        self.header.pack(fill=self.tk.X)
        self.header.bind("<Configure>", self._scheduleHeaderDraw)

    def _scheduleHeaderDraw(self, event=None):
        if self._headerJob is not None:
            try:
                self.window.after_cancel(self._headerJob)
            except Exception:
                pass
        self._headerJob = self.window.after(35, self._drawHeader)

    def _interp(self, color1, color2, ratio):
        a = [int(color1[_:_ + 2], 16) for _ in (1, 3, 5)]
        b = [int(color2[_:_ + 2], 16) for _ in (1, 3, 5)]
        return "#%02x%02x%02x" % tuple(int(a[_] + (b[_] - a[_]) * ratio) for _ in range(3))

    def _drawHeader(self):
        """Draw the header only for resize or process-state changes.

        Keep this deliberately cheap.  Redrawing a canvas from an <Enter>/<Leave>
        callback can remove the item currently under the pointer, which generates a
        matching leave/enter pair and can turn into an event/redraw loop on Tk/X11.
        """
        self._headerJob = None
        p = PALETTE
        c = self.header
        c.delete("all")
        width = max(1, c.winfo_width())
        height = 76

        # A small, fixed number of primitives paints faster and more consistently
        # than a strip-per-gradient header, especially on X11 and remote displays.
        c.create_rectangle(0, 0, width, height, outline="", fill="#17445f")
        c.create_rectangle(0, 0, 6, height, outline="", fill=p["sky"])
        c.create_rectangle(6, height - 4, width, height, outline="", fill="#0e7697")
        c.create_line(22, 64, max(22, width - 160), 64, fill="#39738a")

        c.create_text(26, 26, text="sqlmap", anchor="w", fill="#ffffff", font=self.fonts["title"])
        c.create_text(124, 30, text=VERSION_STRING.replace("sqlmap/", "v"), anchor="w",
                      fill="#bfe1ed", font=self.fonts["subtitle"])
        c.create_text(26, 52, text="automatic SQL injection and database takeover tool", anchor="w",
                      fill="#dcecf2", font=self.fonts["small"])
        self._drawRunButton(width, height)

    def _isRunning(self):
        return self.process is not None and self.process.poll() is None

    def _drawRunButton(self, width, height):
        p = PALETTE
        c = self.header
        running = self._isRunning()
        bw, bh = 116, 34
        x0 = width - bw - 22
        y0 = (height - bh) // 2
        x1, y1 = x0 + bw, y0 + bh
        baseFill = p["red"] if running else p["success"]
        fill = ("#d15056" if running else "#3bae6b") if self._runHover else baseFill
        c.create_rectangle(x0, y0, x1, y1, fill=fill, outline="#d9f1e3", width=1,
                           tags=("runbtn", "runpill"))
        c.create_line(x0 + 1, y0 + 1, x1 - 1, y0 + 1, fill="#8fd2aa" if not running else "#ef9da1",
                      tags="runbtn")
        c.create_line(x0 + 1, y1 - 1, x1 - 1, y1 - 1, fill="#17613a" if not running else "#75252a",
                      tags="runbtn")
        cy = (y0 + y1) // 2
        tx = x0 + 23
        if running:
            c.create_rectangle(tx, cy - 6, tx + 11, cy + 6, fill="#ffffff", outline="",
                               tags=("runbtn", "runico"))
        else:
            c.create_polygon(tx, cy - 6, tx, cy + 6, tx + 10, cy, fill="#ffffff", outline="",
                             tags=("runbtn", "runico"))
        c.create_text((x0 + x1) // 2 + 8, cy, text=("Stop" if running else "Run"), fill="#ffffff",
                      font=self.fonts["bodyBold"], tags=("runbtn", "runico"))
        c.tag_bind("runbtn", "<Button-1>", lambda e: self._runButtonAction())
        c.tag_bind("runbtn", "<Enter>", lambda e: self._hoverRun(True))
        c.tag_bind("runbtn", "<Leave>", lambda e: self._hoverRun(False))

    def _runButtonAction(self):
        if self._isRunning():
            self.stopProcess()
        else:
            self.run()

    def _hoverRun(self, on):
        """Update only the existing button items; never rebuild the header here."""
        self._runHover = on
        try:
            running = self._isRunning()
            if on:
                fill = "#d15056" if running else "#3bae6b"
            else:
                fill = PALETTE["red"] if running else PALETTE["success"]
            self.header.itemconfigure("runpill", fill=fill)
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
        badge = tk.Label(row, text="", background=p["mantle"], foreground=p["navMuted"], font=self.fonts["small"])
        badge.pack(side=tk.RIGHT, padx=(0, 12))
        self.badges[name] = badge
        lab = tk.Label(row, text=navText, background=p["mantle"], foreground=p["navText"],
                       font=self.fonts["nav"], anchor="w", padx=10, pady=9)
        lab.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for w in (row, lab, strip, icon, badge):
            w.bind("<Button-1>", lambda e, n=name: self._selectPane(n))
            w.bind("<Enter>", lambda e, n=name: self._navHover(n, True))
            w.bind("<Leave>", lambda e, n=name: self._navHover(n, False))
        self.navItems[name] = (row, strip, icon, lab, badge)
        self.paneOrder.append(name)

        outer = self.ttk.Frame(self.content, style="Card.TFrame")
        canvas = tk.Canvas(outer, background=p["panel"], highlightthickness=0, borderwidth=0)
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
        if entering:
            self._prioritizePaneBuild(name)
        if name == self.currentPane:
            return
        bg = PALETTE["navHover"] if entering else PALETTE["mantle"]
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
        # Build only a tiny, time-bounded slice synchronously so a never-visited pane
        # appears immediately. The remaining rows are completed by the idle prebuilder.
        if name not in self.built:
            self._prioritizePaneBuild(name)
            self._buildPaneSlice(name, budgetMs=14, minimumSteps=5)
        if self.currentPane == name:
            return
        p = PALETTE
        if self.currentPane:
            self.panes[self.currentPane].pack_forget()
            row, strip, icon, lab, badge = self.navItems[self.currentPane]
            for w in (row, strip, icon):
                w.configure(background=p["mantle"])
            lab.configure(background=p["mantle"], foreground=p["navText"], font=self.fonts["nav"])
            badge.configure(background=p["mantle"], foreground=p["navMuted"])
            self._drawIcon(icon, self.currentPane, self._iconColor(self.currentPane))
        self.panes[name].pack(expand=True, fill=self.tk.BOTH)
        row, strip, icon, lab, badge = self.navItems[name]
        for w in (row, icon):
            w.configure(background=p["blue"])
        strip.configure(background=p["sky"])
        lab.configure(background=p["blue"], foreground="#ffffff", font=self.fonts["bodyBold"])
        badge.configure(background=p["blue"], foreground="#d9edf5")
        self._drawIcon(icon, name, "#ffffff")
        self.currentPane = name
        # Geometry flushing here used to make first-time pane switches feel much
        # slower than the widget creation itself. Sidebar visibility can be fixed
        # on the next idle turn without blocking the click handler.
        self.window.after_idle(lambda n=name: self._ensureNavVisible(n) if self.currentPane == n else None)

        if hasattr(self, "hint"):        # don't leave the previous section's option hint lingering
            self.hint.set(HINT_DEFAULT)

    def _ensureNavVisible(self, name):
        # scroll the sidebar so the active item stays in view (e.g. when paging with Up/Down)
        try:
            row = self.navItems[name][0]
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
        # Route the wheel only when the pointer is actually over this window's sidebar/content.
        rawDelta = getattr(event, "delta", 0)
        if getattr(event, "num", None) == 5:
            delta = 1
        elif getattr(event, "num", None) == 4:
            delta = -1
        else:
            delta = -int(rawDelta / 120) if abs(rawDelta) >= 120 else (-1 if rawDelta > 0 else 1)
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
        if target is not None:
            target.yview_scroll(delta, "units")
            return "break"
        return None

    def _schedulePanePrebuild(self, delay=1):
        if self._prebuildJob is not None:
            return
        try:
            self._prebuildJob = self.window.after(delay, self._pumpPanePrebuild)
        except Exception:
            self._prebuildJob = None

    def _prioritizePaneBuild(self, name):
        if name in self.built:
            return
        try:
            self._prebuildQueue.remove(name)
        except ValueError:
            pass
        self._prebuildQueue.insert(0, name)
        self._schedulePanePrebuild()

    def _buildPaneSlice(self, name, budgetMs=7, minimumSteps=1):
        if name in self.built:
            return True
        builder = self.builders.get(name)
        if builder is None:
            self.built.add(name)
            return True
        state = self.buildStates.get(name)
        if state is None:
            state = builder(self.inners[name])
            self.buildStates[name] = state

        deadline = _clock() + max(0.001, budgetMs / 1000.0)
        steps = 0
        while steps < minimumSteps or _clock() < deadline:
            try:
                next(state)
                steps += 1
            except StopIteration:
                self.buildStates.pop(name, None)
                self.built.add(name)
                try:
                    self._prebuildQueue.remove(name)
                except ValueError:
                    pass
                return True
            except Exception:
                # A broken optional field should not make the whole GUI unusable.
                self.buildStates.pop(name, None)
                self.built.add(name)
                try:
                    self._prebuildQueue.remove(name)
                except ValueError:
                    pass
                return True
        return False

    def _pumpPanePrebuild(self):
        self._prebuildJob = None
        while self._prebuildQueue and self._prebuildQueue[0] in self.built:
            self._prebuildQueue.pop(0)
        if not self._prebuildQueue:
            return

        name = self._prebuildQueue[0]
        finished = self._buildPaneSlice(name, budgetMs=7, minimumSteps=1)
        if finished and self._prebuildQueue and self._prebuildQueue[0] == name:
            self._prebuildQueue.pop(0)
        # Yield to pointer, keyboard, expose and paint events after every small slice.
        self._schedulePanePrebuild(1)

    def _scheduleSearch(self, *unused):
        if self._searchJob is not None:
            try:
                self.window.after_cancel(self._searchJob)
            except Exception:
                pass
        self._searchJob = self.window.after(90, self._applySearch)

    def _applySearch(self):
        self._searchJob = None
        query = self.searchVar.get().strip().lower()
        if not query:
            self.searchMatches = []
            self.searchList.delete(0, self.tk.END)
            self.searchList.pack_forget()
            return

        tokens = query.split()
        matches = []
        for dest, index, label, section, flag, haystack in self.searchIndex:
            if not all(token in haystack for token in tokens):
                continue
            score = 0
            if dest.lower().startswith(query):
                score -= 40
            if flag.lower().startswith(query) or flag.lower().startswith("--" + query):
                score -= 30
            if label.lower().startswith(query):
                score -= 20
            if section.lower().startswith(query):
                score -= 10
            matches.append((score, index, dest, label, section))

        matches.sort()
        matches = matches[:MAX_SEARCH_RESULTS]
        self.searchMatches = [item[2] for item in matches]
        self.searchList.delete(0, self.tk.END)
        for _, _, dest, label, section in matches:
            shortSection = NAV_ALIASES.get(section, section)
            self.searchList.insert(self.tk.END, "%s  [%s]" % (label, shortSection))

        if matches:
            self.searchList.configure(height=min(7, len(matches)))
            self.searchList.pack(fill=self.tk.X, padx=9, pady=(0, 7), before=self.navCanvas)
            self.searchList.selection_clear(0, self.tk.END)
            self.searchList.selection_set(0)
            self.searchList.activate(0)
        else:
            self.searchList.insert(self.tk.END, "No matching options")
            self.searchList.configure(height=1)
            self.searchList.pack(fill=self.tk.X, padx=9, pady=(0, 7), before=self.navCanvas)

    def _searchMoveDown(self, event=None):
        if self.searchMatches:
            self.searchList.focus_set()
            self.searchList.selection_clear(0, self.tk.END)
            self.searchList.selection_set(0)
            self.searchList.activate(0)
        return "break"

    def _clickSearchResult(self, event):
        if not self.searchMatches:
            return "break"
        try:
            index = int(self.searchList.nearest(event.y))
        except Exception:
            index = 0
        if index < 0 or index >= len(self.searchMatches):
            return "break"
        # Resolve the clicked row ourselves instead of depending on Listbox class
        # bindings, whose selection update happens after this widget binding.
        self.searchList.selection_clear(0, self.tk.END)
        self.searchList.selection_set(index)
        self.searchList.activate(index)
        return self._activateSearchIndex(index)

    def _activateSearchResult(self, event=None):
        if not self.searchMatches:
            return "break"
        selection = self.searchList.curselection()
        index = int(selection[0]) if selection else 0
        return self._activateSearchIndex(index)

    def _activateSearchIndex(self, index):
        if not self.searchMatches:
            return "break"
        if index < 0 or index >= len(self.searchMatches):
            index = 0
        dest = self.searchMatches[index]
        section = self.sectionByDest.get(dest)
        self.searchVar.set("")
        if section in self.panes:
            self._selectPane(section)
            self._focusOptionWhenReady(dest, section)
        elif dest == "url":
            self._focusTarget()
        return "break"

    def _focusOptionWhenReady(self, dest, paneName):
        # A search can jump to an option that the incremental pane builder has not
        # created yet. Continue that pane in tiny slices and focus as soon as the
        # requested widget exists, without blocking the click handler.
        for candidatePane, candidateWidget in self.controlsByDest.get(dest, ()):
            if candidatePane == paneName:
                self.window.after_idle(lambda d=dest, p=paneName: self._focusOption(d, p))
                return
        if paneName not in self.built:
            self._prioritizePaneBuild(paneName)
            self._buildPaneSlice(paneName, budgetMs=6, minimumSteps=1)
            self.window.after(1, lambda d=dest, p=paneName: self._focusOptionWhenReady(d, p))

    def _focusOption(self, dest, paneName):
        candidates = self.controlsByDest.get(dest, ())
        widget = None
        for candidatePane, candidateWidget in candidates:
            if candidatePane == paneName:
                widget = candidateWidget
                break
        if widget is None and candidates:
            widget = candidates[0][1]
        if widget is None:
            return
        try:
            widget.focus_set()
            if isinstance(widget, (self.ttk.Entry, self.ttk.Combobox)):
                widget.select_range(0, "end")
            canvas = self.canvases.get(paneName)
            inner = self.inners.get(paneName)
            if canvas is not None and inner is not None:
                inner.update_idletasks()
                total = max(1, inner.winfo_height())
                canvas.yview_moveto(max(0.0, min(1.0, float(widget.winfo_y() - 30) / total)))
        except Exception:
            pass

    def _buildPaneHeading(self, parent, title, description, optionCount):
        p = PALETTE
        card = self.tk.Frame(parent, background=p["surface0"], highlightthickness=1,
                             highlightbackground=p["border"], borderwidth=0)
        card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        accent = self.tk.Frame(card, background=self._iconColor(title), width=5)
        accent.pack(side=self.tk.LEFT, fill=self.tk.Y)
        content = self.ttk.Frame(card, style="PaneHeader.TFrame", padding=(14, 10, 14, 10))
        content.pack(side=self.tk.LEFT, fill=self.tk.BOTH, expand=True)
        titleRow = self.ttk.Frame(content, style="PaneHeader.TFrame")
        titleRow.pack(fill=self.tk.X)
        self.ttk.Label(titleRow, text=title, style="Pane.TLabel").pack(side=self.tk.LEFT)
        self.ttk.Label(titleRow, text="%d option%s" % (optionCount, "" if optionCount == 1 else "s"),
                       style="PaneCount.TLabel").pack(side=self.tk.RIGHT, pady=(6, 0))
        if description:
            self.ttk.Label(content, text=description, style="PanelHint.TLabel", wraplength=690,
                           justify="left").pack(fill=self.tk.X, pady=(3, 0))

    def _buildQuickStartPane(self):
        name = "Quick start"
        self._addPane(name, name)
        self.sectionDests[name] = [_ for _ in QUICK_START_DESTS if _ in self.optionByDest]

        def build(inner):
            description = "The options people reach for most. Set the target above, choose what you need, then Run."
            self._buildPaneHeading(inner, name, description, len(self.sectionDests[name]))
            yield
            row = 1
            for dest in QUICK_START_DESTS:
                option = self.optionByDest.get(dest)
                if option is not None:
                    row = self._buildFieldRow(inner, option, row, paneName=name)
                    yield
            inner.columnconfigure(1, weight=1)

        self.builders[name] = build

    def _buildGroupPane(self, group):
        title = _groupTitle(group)
        self._addPane(title, NAV_ALIASES.get(title, title))
        self.sectionDests[title] = [_optDest(_) for _ in _groupOptions(group) if _optDest(_)]

        def build(inner, group=group, title=title):
            self._buildPaneHeading(inner, title, _groupDescription(group), len(self.sectionDests[title]))
            yield
            row = 1
            for option in _groupOptions(group):
                row = self._buildFieldRow(inner, option, row, paneName=title)
                yield
            inner.columnconfigure(1, weight=1)

        self.builders[title] = build

    def _destVar(self, dest, is_bool):
        # One shared effective-value variable per option, reflected in every duplicate control.
        if dest not in self.vars:
            var = self.tk.BooleanVar(value=False) if is_bool else self.tk.StringVar(value="")
            self.vars[dest] = var
            self.widgets[dest] = ("bool" if is_bool else "string", var)
            try:
                var.trace("w", self._onOptionChanged)
            except Exception:
                pass
        return self.vars[dest]

    def _buildFieldRow(self, parent, option, row, labelText=None, paneName=None):
        label = labelText or _optionLabel(option)
        helptext = _optHelp(option)
        dest = _optDest(option)
        if not dest:
            return row
        is_bool = not _optTakesValue(option)

        if is_bool:
            var = self._destVar(dest, True)
            default = bool(defaults.get(dest))
            chk = self.ttk.Checkbutton(parent, text=label, variable=var,
                                       onvalue=(not default), offvalue=default, takefocus=True)
            chk.grid(row=row, column=0, columnspan=2, sticky="w", pady=5)
            self.tooltip.attach(chk, helptext)
            self.controlsByDest.setdefault(dest, []).append((paneName, chk))
        else:
            otype = _optValueType(option)
            var = self._destVar(dest, False)
            lab = self.ttk.Label(parent, text=label, style="Field.TLabel")
            lab.grid(row=row, column=0, sticky="w", padx=(0, 18), pady=6)
            self.tooltip.attach(lab, helptext)
            choices = _optChoices(option)
            if choices:
                widget = self.ttk.Combobox(parent, values=list(choices), state="readonly", textvariable=var)
            else:
                widget = self.ttk.Entry(parent, textvariable=var)
                if otype in ("int", "float"):
                    self._constrain(widget, otype)
            widget.grid(row=row, column=1, sticky="ew", pady=6)
            self.tooltip.attach(widget, helptext)
            self.controlsByDest.setdefault(dest, []).append((paneName, widget))
        return row + 1

    def _constrain(self, entry, otype):
        def check(proposed):
            if proposed in ("", "+", "-", ".", "+.", "-."):
                return True
            try:
                if otype == "int":
                    int(proposed)
                else:
                    float(proposed)
                return True
            except (TypeError, ValueError):
                return False

        vcmd = (self.window.register(check), "%P")
        entry.configure(validate="key", validatecommand=vcmd)


    # --- helpers --------------------------------------------------------

    def _center(self, window, width=None, height=None):
        window.update_idletasks()
        width = width or window.winfo_width()
        height = height or window.winfo_height()
        x = window.winfo_screenwidth() // 2 - width // 2
        y = window.winfo_screenheight() // 2 - height // 2
        window.geometry("%dx%d+%d+%d" % (width, height, x, y))

    def _isOptionSet(self, dest):
        item = self.widgets.get(dest)
        if item is None:
            return False
        otype, var = item
        try:
            value = var.get()
        except Exception:
            return False
        default = defaults.get(dest)
        if otype == "bool":
            return bool(value) != bool(default)
        if value in (None, ""):
            return False
        displayDefault = "" if default in (None, False) else str(default)
        return str(value) != displayDefault

    def _updateStats(self):
        setDests = set(_ for _ in self.widgets if self._isOptionSet(_))
        count = len(setDests)
        status = "%d option%s set" % (count, "" if count == 1 else "s")
        if self._isRunning():
            status += "  |  running"
        self.stat.set(status)
        for name, dests in self.sectionDests.items():
            badge = self.badges.get(name)
            if badge is not None:
                hits = sum(1 for _ in dests if _ in setDests)
                badge.configure(text=(str(hits) if hits else ""))

    def _buildCommandString(self):
        argv = ["sqlmap.py"]
        for dest in self.optionOrder:
            if not self._isOptionSet(dest):
                continue
            option = self.optionByDest.get(dest)
            flag = _preferredFlag(option) if option is not None else ""
            if not flag:
                continue
            otype, var = self.widgets[dest]
            try:
                argv.append(flag)
                if otype != "bool":
                    argv.append(_toText(var.get()))
            except Exception:
                pass
        if IS_WIN:
            return _list2cmdline(argv)
        return " ".join(_quoteArg(_) for _ in argv)

    def _copyCommand(self):
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(self.command.get())
            self.hint.set("Command copied to clipboard")
        except Exception:
            pass

    def _pasteTarget(self):
        try:
            value = self.window.clipboard_get()
            self.vars["url"].set(_toText(value).strip())
            self.targetEntry.focus_set()
            self.targetEntry.icursor("end")
        except Exception:
            self.hint.set("Clipboard does not contain text")

    def _clearTarget(self):
        try:
            self.vars["url"].set("")
            self.targetEntry.focus_set()
        except Exception:
            pass

    def _focusTarget(self):
        try:
            self.targetEntry.focus_set()
            self.targetEntry.select_range(0, "end")
        except Exception:
            pass
        return "break"

    def _focusSearch(self):
        try:
            self.searchEntry.focus_set()
            self.searchEntry.select_range(0, "end")
        except Exception:
            pass
        return "break"

    def _escapeAction(self, event=None):
        try:
            if self.searchVar.get():
                self.searchVar.set("")
                self.searchEntry.focus_set()
                return "break"
        except Exception:
            pass
        return None

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
                var.set(bool(value))
            else:
                var.set("" if value in (None, False) else value)
        except Exception:
            pass

    def resetOptions(self):
        self._suspendRefresh = True
        try:
            for dest, (otype, var) in self.widgets.items():
                default = defaults.get(dest)
                if otype == "bool":
                    var.set(bool(default))
                else:
                    var.set("" if default in (None, False) else default)
        finally:
            self._suspendRefresh = False
        self._refreshDerivedState()
        self.hint.set("All options reset to their defaults")


    # --- actions --------------------------------------------------------

    def loadConfig(self):
        path = self.filedialog.askopenfilename(title="Load configuration", filetypes=[("sqlmap config", "*.conf *.ini"), ("All files", "*.*")])
        if not path:
            return
        try:
            from thirdparty.six.moves import configparser as _configparser
            parser = _configparser.ConfigParser()
            parser.optionxform = str
            parser.read(path)
            byLower = dict((_.lower(), _) for _ in self.widgets)
            count = 0
            self._suspendRefresh = True
            try:
                for section in parser.sections():
                    for name, value in parser.items(section):
                        dest = name if name in self.widgets else byLower.get(name.lower())
                        if dest is None:
                            continue
                        if self.widgets[dest][0] == "bool":
                            self._setWidgetValue(dest, str(value).lower() in ("1", "true", "yes", "on"))
                        else:
                            self._setWidgetValue(dest, value)
                        count += 1
            finally:
                self._suspendRefresh = False
            self._refreshDerivedState()
            self.hint.set("Loaded %d options from %s" % (count, os.path.basename(path)))
        except Exception as ex:
            self._suspendRefresh = False
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
        if self._isRunning():
            self.hint.set("sqlmap is already running")
            try:
                self.consoleWindow.deiconify()
                self.consoleWindow.lift()
            except Exception:
                pass
            return

        configFile = None
        try:
            config = self._collectConfig()
            handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
            os.close(handle)
            saveConfig(config, configFile)

            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            proc = subprocess.Popen(
                [sys.executable or "python", os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap.py"), "-c", configFile],
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                bufsize=0,
                close_fds=not IS_WIN,
                universal_newlines=False,
                env=env,
            )
        except Exception as ex:
            self._cleanupConfigFile(configFile)
            self.messagebox.showerror("Unable to start sqlmap", getSafeExString(ex))
            return

        self._runSerial += 1
        serial = self._runSerial
        outputQueue = _queue.Queue()
        self.process = proc
        self.processQueue = outputQueue
        self.processConfigFile = configFile

        def enqueue(stream, queue):
            try:
                for line in iter(stream.readline, b""):
                    if not line:
                        break
                    queue.put(_toText(line))
            except Exception as ex:
                queue.put("\n[console reader error: %s]\n" % getSafeExString(ex))
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
                queue.put(None)

        thread = threading.Thread(target=enqueue, args=(proc.stdout, outputQueue))
        thread.daemon = True
        thread.start()

        self.hint.set("sqlmap started")
        self._scheduleHeaderDraw()
        self._refreshDerivedState()
        self._openConsole(proc, outputQueue, serial)
        self.window.after(200, lambda: self._watchProcess(proc, serial, configFile))

    def _watchProcess(self, proc, serial, configFile):
        if proc.poll() is None:
            try:
                self.window.after(200, lambda: self._watchProcess(proc, serial, configFile))
            except Exception:
                pass
            return

        self._cleanupConfigFile(configFile)
        if self.process is proc and self._runSerial == serial:
            self.process = None
            self.processQueue = None
            self.processConfigFile = None
            self._scheduleHeaderDraw()
            self._refreshDerivedState()
            self.hint.set("sqlmap finished with exit code %s" % proc.returncode)

    def stopProcess(self, proc=None):
        proc = proc or self.process
        if proc is None or proc.poll() is not None:
            return
        self.hint.set("Stopping sqlmap...")
        try:
            if self.consoleStatus is not None:
                self.consoleStatus.set("Stopping...")
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception as ex:
            self.messagebox.showerror("Unable to stop sqlmap", getSafeExString(ex))
            return

        def forceKill():
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

        self.window.after(1800, forceKill)

    def _cleanupConfigFile(self, path):
        if path:
            try:
                os.remove(path)
            except OSError:
                pass

    def _appendConsole(self, text, content, forceScroll=False):
        if not content:
            return
        try:
            atBottom = text.yview()[1] >= 0.985
            text.configure(state="normal")
            text.insert(self.tk.END, content)
            lineCount = int(float(text.index("end-1c").split(".")[0]))
            if lineCount > MAX_CONSOLE_LINES:
                text.delete("1.0", "%d.0" % (lineCount - MAX_CONSOLE_LINES))
            text.configure(state="disabled")
            if forceScroll or atBottom:
                text.see(self.tk.END)
        except Exception:
            pass

    def _openConsole(self, proc, outputQueue, serial):
        p = PALETTE
        tk = self.tk
        try:
            if self.consoleWindow is not None and self.consoleWindow.winfo_exists():
                self.consoleWindow.destroy()
        except Exception:
            pass

        top = tk.Toplevel(self.window)
        self.consoleWindow = top
        top.title("sqlmap - console")
        top.configure(background=p["base"])

        toolbar = self.ttk.Frame(top, style="Bar.TFrame", padding=(10, 8))
        toolbar.pack(fill=tk.X)
        status = tk.StringVar(value="Running")
        self.consoleStatus = status
        self.ttk.Label(toolbar, textvariable=status, style="Stat.TLabel").pack(side=tk.LEFT)
        stopButton = self.ttk.Button(toolbar, text="Stop", command=lambda: self.stopProcess(proc))
        stopButton.pack(side=tk.RIGHT, padx=(8, 0))
        self.ttk.Button(toolbar, text="Save log...", command=lambda: self._saveConsoleLog(text)).pack(side=tk.RIGHT, padx=(8, 0))
        self.ttk.Button(toolbar, text="Clear", command=lambda: self._clearConsole(text)).pack(side=tk.RIGHT)

        frame = self.ttk.Frame(top, style="Card.TFrame", padding=(10, 0, 10, 8))
        frame.pack(fill=tk.BOTH, expand=True)
        text = self.scrolledtext.ScrolledText(frame, wrap=tk.NONE, bg=p["crust"], fg=p["consoleText"],
                                              insertbackground=p["commandText"], selectbackground=p["sapphire"],
                                              selectforeground="#ffffff", relief="sunken", borderwidth=2,
                                              font=self.fonts["mono"], padx=12, pady=10, state="disabled")
        text.pack(fill=tk.BOTH, expand=True)
        self.consoleText = text
        self._appendConsole(text, "$ %s\n\n" % self.command.get(), forceScroll=True)

        inputBar = self.ttk.Frame(top, style="Bar.TFrame", padding=(10, 0, 10, 10))
        inputBar.pack(fill=tk.X)
        self.ttk.Label(inputBar, text="Input:", style="Hint.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        inputVar = tk.StringVar(value="")
        inputEntry = self.ttk.Entry(inputBar, textvariable=inputVar)
        inputEntry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def sendInput(event=None):
            value = inputVar.get()
            if proc.poll() is not None:
                return "break"
            try:
                proc.stdin.write(_toBytes(_toText(value) + u"\n"))
                proc.stdin.flush()
                self._appendConsole(text, "> %s\n" % value, forceScroll=True)
                inputVar.set("")
            except Exception as ex:
                self._appendConsole(text, "[input error: %s]\n" % getSafeExString(ex), forceScroll=True)
            return "break"

        self.ttk.Button(inputBar, text="Send", command=sendInput).pack(side=tk.RIGHT, padx=(8, 0))
        inputEntry.bind("<Return>", sendInput)
        inputEntry.focus_set()

        state = {"readerDone": False, "finishedShown": False}

        def pump():
            try:
                if not top.winfo_exists():
                    return
            except Exception:
                return

            chunks = []
            size = 0
            for _ in range(256):
                try:
                    item = outputQueue.get_nowait()
                except _queue.Empty:
                    break
                if item is None:
                    state["readerDone"] = True
                    break
                chunks.append(item)
                size += len(item)
                if size >= 131072:
                    break
            if chunks:
                self._appendConsole(text, "".join(chunks))

            finished = proc.poll() is not None and state["readerDone"] and outputQueue.empty()
            if finished and not state["finishedShown"]:
                state["finishedShown"] = True
                code = proc.returncode
                self._appendConsole(text, "\n--- process finished (exit code %s) ---\n" % code, forceScroll=True)
                status.set("Finished (exit code %s)" % code)
                try:
                    inputEntry.configure(state="disabled")
                    stopButton.configure(state="disabled")
                except Exception:
                    pass
                return
            top.after(45 if chunks else 90, pump)

        def closeConsole():
            if proc.poll() is None:
                if not self.messagebox.askyesno("Close console", "Stop the running sqlmap process and close the console?"):
                    return
                self.stopProcess(proc)
            try:
                top.destroy()
            except Exception:
                pass
            if self.consoleWindow is top:
                self.consoleWindow = None
                self.consoleText = None
                self.consoleStatus = None

        top.protocol("WM_DELETE_WINDOW", closeConsole)
        self._center(top, 920, 600)
        top.after(45, pump)

    def _clearConsole(self, text):
        try:
            text.configure(state="normal")
            text.delete("1.0", self.tk.END)
            text.configure(state="disabled")
        except Exception:
            pass

    def _saveConsoleLog(self, text):
        path = self.filedialog.asksaveasfilename(title="Save console log", defaultextension=".log",
                                                 filetypes=[("Log file", "*.log"), ("Text file", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with io.open(path, "w", encoding="utf-8") as handle:
                handle.write(_toText(text.get("1.0", "end-1c")))
            self.hint.set("Saved console log to %s" % os.path.basename(path))
        except Exception as ex:
            self.messagebox.showerror("Save log failed", getSafeExString(ex))

    def _closeApplication(self):
        proc = self.process
        if proc is not None and proc.poll() is None:
            if not self.messagebox.askyesno("Exit sqlmap GUI", "Stop the running sqlmap process and exit?"):
                return
            try:
                proc.terminate()
                try:
                    _waitForProcess(proc, 1.2)
                    if proc.poll() is None:
                        proc.kill()
                except Exception:
                    proc.kill()
            except Exception:
                pass
        self._cleanupConfigFile(self.processConfigFile)
        try:
            self.window.destroy()
        except Exception:
            pass


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
