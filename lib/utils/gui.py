#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
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

alive = None
line = ""
process = None
queue = None

def runGui(parser):
    try:
        from thirdparty.six.moves import tkinter as _tkinter
        from thirdparty.six.moves import tkinter_scrolledtext as _tkinter_scrolledtext
        from thirdparty.six.moves import tkinter_ttk as _tkinter_ttk
        from thirdparty.six.moves import tkinter_messagebox as _tkinter_messagebox
    except ImportError as ex:
        raise SqlmapMissingDependence("missing dependence ('%s')" % getSafeExString(ex))

    # Reference: https://www.reddit.com/r/learnpython/comments/985umy/limit_user_input_to_only_int_with_tkinter/e4dj9k9?utm_source=share&utm_medium=web2x
    class ConstrainedEntry(_tkinter.Entry):
        def __init__(self, master=None, **kwargs):
            self.var = _tkinter.StringVar()
            self.regex = kwargs["regex"]
            del kwargs["regex"]
            _tkinter.Entry.__init__(self, master, textvariable=self.var, **kwargs)
            self.old_value = ''
            self.var.trace('w', self.check)
            self.get, self.set = self.var.get, self.var.set

        def check(self, *args):
            if re.search(self.regex, self.get()):
                self.old_value = self.get()
            else:
                self.set(self.old_value)

    try:
        window = _tkinter.Tk()
    except Exception as ex:
        errMsg = "unable to create GUI window ('%s')" % getSafeExString(ex)
        raise SqlmapSystemException(errMsg)

    window.title(VERSION_STRING)

    # Set theme and colors
    bg_color = "#f5f5f5"
    fg_color = "#333333"
    accent_color = "#2c7fb8"
    window.configure(background=bg_color)

    # Configure styles
    style = _tkinter_ttk.Style()

    # Try to use a more modern theme if available
    available_themes = style.theme_names()
    if 'clam' in available_themes:
        style.theme_use('clam')
    elif 'alt' in available_themes:
        style.theme_use('alt')

    # Configure notebook style
    style.configure("TNotebook", background=bg_color)
    style.configure("TNotebook.Tab",
                   padding=[10, 4],
                   background="#e1e1e1",
                   font=('Helvetica', 9))
    style.map("TNotebook.Tab",
             background=[("selected", accent_color), ("active", "#7fcdbb")],
             foreground=[("selected", "white"), ("active", "white")])

    # Configure button style
    style.configure("TButton",
                   padding=4,
                   relief="flat",
                   background=accent_color,
                   foreground="white",
                   font=('Helvetica', 9))
    style.map("TButton",
             background=[('active', '#41b6c4')])

    # Reference: https://stackoverflow.com/a/10018670
    def center(window):
        window.update_idletasks()
        width = window.winfo_width()
        frm_width = window.winfo_rootx() - window.winfo_x()
        win_width = width + 2 * frm_width
        height = window.winfo_height()
        titlebar_height = window.winfo_rooty() - window.winfo_y()
        win_height = height + titlebar_height + frm_width
        x = window.winfo_screenwidth() // 2 - win_width // 2
        y = window.winfo_screenheight() // 2 - win_height // 2
        window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        window.deiconify()

    def onKeyPress(event):
        global line
        global queue

        if process:
            if event.char == '\b':
                line = line[:-1]
            else:
                line += event.char

    def onReturnPress(event):
        global line
        global queue

        if process:
            try:
                process.stdin.write(("%s\n" % line.strip()).encode())
                process.stdin.flush()
            except socket.error:
                line = ""
                event.widget.master.master.destroy()
                return "break"
            except:
                return

            event.widget.insert(_tkinter.END, "\n")

            return "break"

    def run():
        global alive
        global process
        global queue

        config = {}

        for key in window._widgets:
            dest, widget_type = key
            widget = window._widgets[key]

            if hasattr(widget, "get") and not widget.get():
                value = None
            elif widget_type == "string":
                value = widget.get()
            elif widget_type == "float":
                value = float(widget.get())
            elif widget_type == "int":
                value = int(widget.get())
            else:
                value = bool(widget.var.get())

            config[dest] = value

        for option in parser.option_list:
            # Only set default if not already set by the user
            if option.dest not in config or config[option.dest] is None:
                config[option.dest] = defaults.get(option.dest, None)

        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
        os.close(handle)

        saveConfig(config, configFile)

        def enqueue(stream, queue):
            global alive

            for line in iter(stream.readline, b''):
                queue.put(line)

            alive = False
            stream.close()

        alive = True

        process = subprocess.Popen([sys.executable or "python", os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap.py"), "-c", configFile], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, bufsize=1, close_fds=not IS_WIN)

        # Reference: https://stackoverflow.com/a/4896288
        queue = _queue.Queue()
        thread = threading.Thread(target=enqueue, args=(process.stdout, queue))
        thread.daemon = True
        thread.start()

        top = _tkinter.Toplevel()
        top.title("Console")
        top.configure(background=bg_color)

        # Create a frame for the console
        console_frame = _tkinter.Frame(top, bg=bg_color)
        console_frame.pack(fill=_tkinter.BOTH, expand=True, padx=10, pady=10)

        # Reference: https://stackoverflow.com/a/13833338
        text = _tkinter_scrolledtext.ScrolledText(console_frame, undo=True, wrap=_tkinter.WORD,
                                                bg="#2c3e50", fg="#ecf0f1",
                                                insertbackground="white",
                                                font=('Consolas', 10))
        text.bind("<Key>", onKeyPress)
        text.bind("<Return>", onReturnPress)
        text.pack(fill=_tkinter.BOTH, expand=True)
        text.focus()

        center(top)

        while True:
            line = ""
            try:
                line = queue.get(timeout=.1)
                text.insert(_tkinter.END, line)
            except _queue.Empty:
                text.see(_tkinter.END)
                text.update_idletasks()

                if not alive:
                    break

    # Create a menu bar
    menubar = _tkinter.Menu(window, bg=bg_color, fg=fg_color)

    filemenu = _tkinter.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color)
    filemenu.add_command(label="Open", state=_tkinter.DISABLED)
    filemenu.add_command(label="Save", state=_tkinter.DISABLED)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=window.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    menubar.add_command(label="Run", command=run)

    helpmenu = _tkinter.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color)
    helpmenu.add_command(label="Official site", command=lambda: webbrowser.open(SITE))
    helpmenu.add_command(label="Github pages", command=lambda: webbrowser.open(GIT_PAGE))
    helpmenu.add_command(label="Wiki pages", command=lambda: webbrowser.open(WIKI_PAGE))
    helpmenu.add_command(label="Report issue", command=lambda: webbrowser.open(ISSUES_PAGE))
    helpmenu.add_separator()
    helpmenu.add_command(label="About", command=lambda: _tkinter_messagebox.showinfo("About", "Copyright (c) 2006-2025\n\n    (%s)" % DEV_EMAIL_ADDRESS))
    menubar.add_cascade(label="Help", menu=helpmenu)

    window.config(menu=menubar, bg=bg_color)
    window._widgets = {}

    # Create header frame
    header_frame = _tkinter.Frame(window, bg=bg_color, height=60)
    header_frame.pack(fill=_tkinter.X, pady=(0, 5))
    header_frame.pack_propagate(0)

    # Add header label
    title_label = _tkinter.Label(header_frame, text="Configuration",
                                font=('Helvetica', 14),
                                fg=accent_color, bg=bg_color)
    title_label.pack(side=_tkinter.LEFT, padx=15)

    # Add run button in header
    run_button = _tkinter_ttk.Button(header_frame, text="Run", command=run, width=12)
    run_button.pack(side=_tkinter.RIGHT, padx=15)

    # Create notebook
    notebook = _tkinter_ttk.Notebook(window)
    notebook.pack(expand=1, fill="both", padx=5, pady=(0, 5))

    # Store tab information for background loading
    tab_frames = {}
    tab_canvases = {}
    tab_scrollable_frames = {}
    tab_groups = {}

    # Create empty tabs with scrollable areas first (fast)
    for group in parser.option_groups:
        # Create a frame with scrollbar for the tab
        tab_frame = _tkinter.Frame(notebook, bg=bg_color)
        tab_frames[group.title] = tab_frame

        # Create a canvas with scrollbar
        canvas = _tkinter.Canvas(tab_frame, bg=bg_color, highlightthickness=0)
        scrollbar = _tkinter_ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = _tkinter.Frame(canvas, bg=bg_color)

        # Store references
        tab_canvases[group.title] = canvas
        tab_scrollable_frames[group.title] = scrollable_frame
        tab_groups[group.title] = group

        # Configure the canvas scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack the canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Add the tab to the notebook
        notebook.add(tab_frame, text=group.title)

        # Add a loading indicator
        loading_label = _tkinter.Label(scrollable_frame, text="Loading options...",
                                     font=('Helvetica', 12),
                                     fg=accent_color, bg=bg_color)
        loading_label.pack(expand=True)

    # Function to populate a tab in the background
    def populate_tab(tab_name):
        group = tab_groups[tab_name]
        scrollable_frame = tab_scrollable_frames[tab_name]
        canvas = tab_canvases[tab_name]

        # Remove loading indicator
        for child in scrollable_frame.winfo_children():
            child.destroy()

        # Add content to the scrollable frame
        row = 0

        if group.get_description():
            desc_label = _tkinter.Label(scrollable_frame, text=group.get_description(),
                                      wraplength=600, justify="left",
                                      font=('Helvetica', 9),
                                      fg="#555555", bg=bg_color)
            desc_label.grid(row=row, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 5))
            row += 1

        for option in group.option_list:
            # Option label
            option_label = _tkinter.Label(scrollable_frame,
                                        text=parser.formatter._format_option_strings(option) + ":",
                                        font=('Helvetica', 9),
                                        fg=fg_color, bg=bg_color,
                                        anchor="w")
            option_label.grid(row=row, column=0, sticky="w", padx=10, pady=2)

            # Input widget
            if option.type == "string":
                widget = _tkinter.Entry(scrollable_frame, font=('Helvetica', 9),
                                      relief="sunken", bd=1, width=20)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            elif option.type == "float":
                widget = ConstrainedEntry(scrollable_frame, regex=r"\A\d*\.?\d*\Z",
                                        font=('Helvetica', 9),
                                        relief="sunken", bd=1, width=10)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            elif option.type == "int":
                widget = ConstrainedEntry(scrollable_frame, regex=r"\A\d*\Z",
                                        font=('Helvetica', 9),
                                        relief="sunken", bd=1, width=10)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            else:
                var = _tkinter.IntVar()
                widget = _tkinter.Checkbutton(scrollable_frame, variable=var,
                                            bg=bg_color, activebackground=bg_color)
                widget.var = var
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)

            # Help text (truncated to improve performance)
            help_text = option.help
            if len(help_text) > 100:
                help_text = help_text[:100] + "..."

            help_label = _tkinter.Label(scrollable_frame, text=help_text,
                                      font=('Helvetica', 8),
                                      fg="#666666", bg=bg_color,
                                      wraplength=400, justify="left")
            help_label.grid(row=row, column=2, sticky="w", padx=5, pady=2)

            # Store widget reference
            window._widgets[(option.dest, option.type)] = widget

            # Set default value
            default = defaults.get(option.dest)
            if default:
                if hasattr(widget, "insert"):
                    widget.insert(0, default)
                elif hasattr(widget, "var"):
                    widget.var.set(1 if default else 0)

            row += 1

        # Add some padding at the bottom
        _tkinter.Label(scrollable_frame, bg=bg_color, height=1).grid(row=row, column=0)

        # Update the scroll region after adding all widgets
        canvas.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        # Update the UI to show the tab is fully loaded
        window.update_idletasks()

    # Function to populate tabs in the background
    def populate_tabs_background():
        for tab_name in tab_groups.keys():
            # Schedule each tab to be populated with a small delay between them
            window.after(100, lambda name=tab_name: populate_tab(name))

    # Start populating tabs in the background after a short delay
    window.after(500, populate_tabs_background)

    # Set minimum window size
    window.update()
    window.minsize(800, 500)

    # Center the window on screen
    center(window)

    # Start the GUI
    window.mainloop()
