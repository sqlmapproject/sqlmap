#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import socket
import subprocess
import sys
import threading
import webbrowser

from lib.core.common import getSafeExString
from lib.core.defaults import defaults
from lib.core.exception import SqlmapMissingDependence
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import ISSUES_PAGE
from lib.core.settings import GIT_PAGE
from lib.core.settings import SITE
from lib.core.settings import VERSION_STRING
from lib.core.settings import WIKI_PAGE
from thirdparty.six.moves import tkinter_messagebox as _tkinter_messagebox
from thirdparty.six.moves import queue as _queue

line = ""
process = None
queue = None

def runGui(parser):
    try:
        import tkinter
        import tkinter.scrolledtext
        import tkinter.ttk
    except ImportError as ex:
        raise SqlmapMissingDependence("missing dependence ('%s')" % getSafeExString(ex))

    # Reference: https://www.reddit.com/r/learnpython/comments/985umy/limit_user_input_to_only_int_with_tkinter/e4dj9k9?utm_source=share&utm_medium=web2x
    class ConstrainedEntry(tkinter.Entry):
        def __init__(self, master=None, **kwargs):
            self.var = tkinter.StringVar()
            self.regex = kwargs["regex"]
            del kwargs["regex"]
            tkinter.Entry.__init__(self, master, textvariable=self.var, **kwargs)
            self.old_value = ''
            self.var.trace('w', self.check)
            self.get, self.set = self.var.get, self.var.set

        def check(self, *args):
            if re.search(self.regex, self.get()):
                self.old_value = self.get()
            else:
                self.set(self.old_value)

    # Reference: https://code.activestate.com/recipes/580726-tkinter-notebook-that-fits-to-the-height-of-every-/
    class AutoresizableNotebook(tkinter.ttk.Notebook):
        def __init__(self, master=None, **kw):
            tkinter.ttk.Notebook.__init__(self, master, **kw)
            self.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        def _on_tab_changed(self,event):
            event.widget.update_idletasks()

            tab = event.widget.nametowidget(event.widget.select())
            event.widget.configure(height=tab.winfo_reqheight())

    window = tkinter.Tk()
    window.title(VERSION_STRING)

    # Reference: https://www.holadevs.com/pregunta/64750/change-selected-tab-color-in-ttknotebook
    style = tkinter.ttk.Style()
    settings = {"TNotebook.Tab": {"configure": {"padding": [5, 1], "background": "#fdd57e" }, "map": {"background": [("selected", "#C70039"), ("active", "#fc9292")], "foreground": [("selected", "#ffffff"), ("active", "#000000")]}}}
    style.theme_create("custom", parent="alt", settings=settings)
    style.theme_use("custom")

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

            event.widget.insert(tkinter.END, "\n")

            counter = 0
            while True:
                line = ""
                try:
                    #line = queue.get_nowait()
                    line = queue.get(timeout=.1)
                    event.widget.insert(tkinter.END, line)
                    counter = 0
                except _queue.Empty:
                    event.widget.see(tkinter.END)
                    event.widget.update_idletasks()
                    if counter > 3:
                        break
                    else:
                        counter += 1

            return "break"

    def run():
        global process
        global queue

        ON_POSIX = "posix" in sys.builtin_module_names

        def enqueue(stream, queue):
            for line in iter(stream.readline, b''):
                queue.put(line)
            stream.close()

        process = subprocess.Popen("/bin/bash", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, bufsize=1, close_fds=ON_POSIX)

        # Reference: https://stackoverflow.com/a/4896288
        queue = _queue.Queue()
        thread = threading.Thread(target=enqueue, args=(process.stdout, queue))
        thread.daemon = True
        thread.start()


        options = {}

        for key in window._widgets:
            dest, type = key
            widget = window._widgets[key]

            if hasattr(widget, "get") and not widget.get():
                value = None
            elif type == "string":
                value = widget.get()
            elif type == "float":
                value = float(widget.get())
            elif type == "int":
                value = int(widget.get())
            else:
                value = bool(widget.var.get())

            options[dest] = value

        for option in parser.option_list:
            options[option.dest] = defaults.get(option.dest, None)

        parser._args = options

        top = tkinter.Toplevel()
        top.title("Console")

        # Reference: https://stackoverflow.com/a/13833338
        text = tkinter.scrolledtext.ScrolledText(top, undo=True)
        text.bind("<Key>", onKeyPress)
        text.bind("<Return>", onReturnPress)
        text.pack()
        text.focus()

        center(top)

    menubar = tkinter.Menu(window)

    filemenu = tkinter.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Open", state=tkinter.DISABLED)
    filemenu.add_command(label="Save", state=tkinter.DISABLED)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=window.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    menubar.add_command(label="Run", command=run)

    helpmenu = tkinter.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Official site", command=lambda: webbrowser.open(SITE))
    helpmenu.add_command(label="Github pages", command=lambda: webbrowser.open(GIT_PAGE))
    helpmenu.add_command(label="Wiki pages", command=lambda: webbrowser.open(WIKI_PAGE))
    helpmenu.add_command(label="Report issue", command=lambda: webbrowser.open(ISSUES_PAGE))
    helpmenu.add_separator()
    helpmenu.add_command(label="About", command=lambda: _tkinter_messagebox.showinfo("About", "Copyright (c) 2006-2019\n\n    (%s)" % DEV_EMAIL_ADDRESS))
    menubar.add_cascade(label="Help", menu=helpmenu)

    window.config(menu=menubar)
    window._widgets = {}

    notebook = AutoresizableNotebook(window)

    first = None
    frames = {}

    for group in parser.option_groups:
        frame = frames[group.title] = tkinter.Frame(notebook, width=200, height=200)
        notebook.add(frames[group.title], text=group.title)

        tkinter.Label(frame).grid(column=0, row=0, sticky=tkinter.W)

        row = 1
        if group.get_description():
            tkinter.Label(frame, text="%s:" % group.get_description()).grid(column=0, row=1, columnspan=3, sticky=tkinter.W)
            tkinter.Label(frame).grid(column=0, row=2, sticky=tkinter.W)
            row += 2

        for option in group.option_list:
            tkinter.Label(frame, text="%s " % parser.formatter._format_option_strings(option)).grid(column=0, row=row, sticky=tkinter.W)

            if option.type == "string":
                widget = tkinter.Entry(frame)
            elif option.type == "float":
                widget = ConstrainedEntry(frame, regex=r"\A\d*\.?\d*\Z")
            elif option.type == "int":
                widget = ConstrainedEntry(frame, regex=r"\A\d*\Z")
            else:
                var = tkinter.IntVar()
                widget = tkinter.Checkbutton(frame, variable=var)
                widget.var = var

            first = first or widget
            widget.grid(column=1, row=row, sticky=tkinter.W)

            window._widgets[(option.dest, option.type)] = widget

            default = defaults.get(option.dest)
            if default:
                if hasattr(widget, "insert"):
                    widget.insert(0, default)

            tkinter.Label(frame, text=" %s" % option.help).grid(column=2, row=row, sticky=tkinter.W)

            row += 1

        tkinter.Label(frame).grid(column=0, row=row, sticky=tkinter.W)

    notebook.pack(expand=1, fill="both")
    notebook.enable_traversal()

    first.focus()

    window.mainloop()