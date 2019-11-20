#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

def runGui(parser):
    import re
    import tkinter as tk
    from tkinter import ttk

    from lib.core.defaults import defaults

    # Reference: https://www.reddit.com/r/learnpython/comments/985umy/limit_user_input_to_only_int_with_tkinter/e4dj9k9?utm_source=share&utm_medium=web2x
    class ConstrainedEntry(tk.Entry):
        def __init__(self, master=None, **kwargs):
            self.var = tk.StringVar()
            self.regex = kwargs["regex"]
            del kwargs["regex"]
            tk.Entry.__init__(self, master, textvariable=self.var, **kwargs)
            self.old_value = ''
            self.var.trace('w', self.check)
            self.get, self.set = self.var.get, self.var.set

        def check(self, *args):
            if re.search(self.regex, self.get()):
                self.old_value = self.get()
            else:
                self.set(self.old_value)

    # Reference: https://code.activestate.com/recipes/580726-tkinter-notebook-that-fits-to-the-height-of-every-/
    class AutoresizableNotebook(ttk.Notebook):
        def __init__(self, master=None, **kw):
            ttk.Notebook.__init__(self, master, **kw)
            self.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        def _on_tab_changed(self,event):
            event.widget.update_idletasks()

            tab = event.widget.nametowidget(event.widget.select())
            event.widget.configure(height=tab.winfo_reqheight())

    window = tk.Tk()
    window.title("sqlmap")

    # Reference: https://www.holadevs.com/pregunta/64750/change-selected-tab-color-in-ttknotebook
    style = ttk.Style()
    settings = {"TNotebook.Tab": {"configure": {"padding": [5, 1], "background": "#fdd57e" }, "map": {"background": [("selected", "#C70039"), ("active", "#fc9292")], "foreground": [("selected", "#ffffff"), ("active", "#000000")]}}}
    style.theme_create("custom", parent="alt", settings=settings)
    style.theme_use("custom")

    def dummy():
        pass

    menubar = tk.Menu(window)

    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Open", command=dummy)
    filemenu.add_command(label="Save", command=dummy)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=window.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    runmenu = tk.Menu(menubar, tearoff=0)
    runmenu.add_command(label="Start", command=dummy)
    runmenu.add_command(label="Stop", command=dummy)
    menubar.add_cascade(label="Run", menu=runmenu)

    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Wiki pages", command=dummy)
    helpmenu.add_command(label="Official site", command=dummy)
    helpmenu.add_separator()
    helpmenu.add_command(label="About", command=dummy)
    menubar.add_cascade(label="Help", menu=helpmenu)

    window.config(menu=menubar)

    notebook = AutoresizableNotebook(window)

    frames = {}
    for group in parser.option_groups:
        frame = frames[group.title] = tk.Frame(notebook, width=200, height=200)
        notebook.add(frames[group.title], text=group.title)

        tk.Label(frame).grid(column=0, row=0, sticky=tk.W)

        row = 1
        if group.get_description():
            tk.Label(frame, text="%s:" % group.get_description()).grid(column=0, row=1, columnspan=3, sticky=tk.W)
            tk.Label(frame).grid(column=0, row=2, sticky=tk.W)
            row += 2

        for option in group.option_list:
            tk.Label(frame, text="%s " % parser.formatter._format_option_strings(option)).grid(column=0, row=row, sticky=tk.W)

            if option.type == "string":
                widget = tk.Entry(frame)
            elif option.type == "float":
                widget = ConstrainedEntry(frame, regex=r"\A\d*\.?\d*\Z")
            elif option.type == "int":
                widget = ConstrainedEntry(frame, regex=r"\A\d*\Z")
            else:
                var = tk.IntVar()
                widget = tk.Checkbutton(frame, variable=var)
                widget.var = var

            widget.grid(column=1, row=row, sticky=tk.W)

            default = defaults.get(option.dest)
            if default:
                if hasattr(widget, "insert"):
                    widget.insert(0, default)

            tk.Label(frame, text=" %s" % option.help).grid(column=2, row=row, sticky=tk.W)

            row += 1

        tk.Label(frame).grid(column=0, row=row, sticky=tk.W)

    notebook.pack(expand=1, fill="both")

    notebook.enable_traversal()

    window.mainloop()