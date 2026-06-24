#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import subprocess
import sys
import tempfile

try:
    import curses
except ImportError:
    curses = None

from lib.core.common import getSafeExString
from lib.core.common import saveConfig
from lib.core.data import paths
from lib.core.defaults import defaults
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapSystemException
from lib.core.settings import IS_WIN
from thirdparty.six.moves import configparser as _configparser

# Options surfaced on the curated "Quick start" tab (by destination), in display order
QUICK_START_DESTS = (
    "url", "data", "cookie", "dbms", "level", "risk", "technique",
    "getCurrentUser", "getCurrentDb", "getBanner", "isDba",
    "getDbs", "getTables", "getColumns", "getPasswordHashes", "dumpTable",
    "batch", "threads", "proxy", "tor",
)

# Short tab labels so the (sometimes verbose) option-group titles fit the top bar
TAB_ALIASES = {
    "Optimization": "Optimize",
    "Enumeration": "Enumerate",
    "Brute force": "Brute",
    "User-defined function injection": "UDF",
    "File system access": "Files",
    "Operating system access": "OS",
    "Windows registry access": "Registry",
    "Miscellaneous": "Misc",
}

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
    if hasattr(option, "option_strings"):
        return list(option.option_strings)
    return list(getattr(option, "_short_opts", None) or []) + list(getattr(option, "_long_opts", None) or [])

def _optDest(option):
    return getattr(option, "dest", None)

def _optHelp(option):
    return getattr(option, "help", "") or ""

def _optTakesValue(option):
    if hasattr(option, "takes_value"):
        try:
            return option.takes_value()
        except Exception:
            pass
    return getattr(option, "nargs", 1) != 0

def _optValueType(option):
    kind = getattr(option, "type", None)
    if kind in ("int", int):
        return "int"
    if kind in ("float", float):
        return "float"
    return "string"

class NcursesUI:
    def __init__(self, stdscr, parser):
        self.stdscr = stdscr
        self.parser = parser
        self.current_tab = 0
        self.current_field = 0
        self.scroll_offset = 0
        self.tabs = []
        self.fields = {}
        self.running = False
        self.process = None

        # Initialize colors
        self._init_colors()

        # Setup curses
        curses.curs_set(0)
        self.stdscr.keypad(1)

        # Parse option groups
        self._parse_options()

    def _init_colors(self):
        """Cohesive palette: a flat 256-color scheme with a graceful 8-color fallback"""
        curses.start_color()
        try:
            curses.use_default_colors()
            default_bg = -1
        except curses.error:
            default_bg = curses.COLOR_BLACK

        if curses.COLORS >= 256:
            accent, accent_fg, sel_bg = 75, 234, 237
            text, muted, green, red = 252, 245, 114, 210
            curses.init_pair(1, accent_fg, accent)     # header / footer bar
            curses.init_pair(2, accent_fg, accent)     # active tab
            curses.init_pair(3, muted, 236)            # inactive tab
            curses.init_pair(4, accent, sel_bg)        # selected field row
            curses.init_pair(5, muted, default_bg)     # help / description
            curses.init_pair(6, red, default_bg)       # error / important
            curses.init_pair(7, text, default_bg)      # label / value
            curses.init_pair(8, green, default_bg)     # value that has been set
            curses.init_pair(9, muted, sel_bg)         # help text on the highlighted row
        else:
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(5, curses.COLOR_GREEN, default_bg)
            curses.init_pair(6, curses.COLOR_RED, default_bg)
            curses.init_pair(7, curses.COLOR_WHITE, default_bg)
            curses.init_pair(8, curses.COLOR_GREEN, default_bg)
            curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_CYAN)

    def _parse_options(self):
        """Parse command line options into tabs and fields"""
        self.all_options = []
        for group in _parserGroups(self.parser):
            title = _groupTitle(group)
            tab_data = {
                'title': title,
                'description': _groupDescription(group),
                'options': []
            }

            for option in _groupOptions(group):
                dest = _optDest(option)
                if not dest:
                    continue
                field_data = {
                    'dest': dest,
                    'label': self._format_option_strings(option),
                    'help': _optHelp(option),
                    'type': _optValueType(option) if _optTakesValue(option) else 'bool',
                    'value': '',
                    'default': defaults.get(dest) if defaults.get(dest) else None
                }
                tab_data['options'].append(field_data)
                self.fields[(title, dest)] = field_data
                self.all_options.append(field_data)

            self.tabs.append(tab_data)

        # curated "Quick start" tab; references the same field objects as the group tabs,
        # so a value edited in either place stays in sync
        seen = {}
        for tab in self.tabs:
            for option in tab['options']:
                seen.setdefault(option['dest'], option)
        quick = {
            'title': 'Quick start',
            'description': "The options people reach for most. Fill these in, then press F2 to run.",
            'options': [seen[dest] for dest in QUICK_START_DESTS if dest in seen],
        }
        if quick['options']:
            self.tabs.insert(0, quick)

    def _format_option_strings(self, option):
        """Format option strings for display"""
        return ', '.join(_optStrings(option))

    def _tab_title(self, tab):
        return TAB_ALIASES.get(tab['title'], tab['title'])

    def _draw_header(self):
        """Draw the header bar"""
        height, width = self.stdscr.getmaxyx()
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, " " * width)
        self.stdscr.addstr(0, 1, "sqlmap")
        self.stdscr.attroff(curses.A_BOLD)
        right = "F2 Run  -  F10 Quit "
        try:
            self.stdscr.addstr(0, max(8, width - len(right)), right)
        except:
            pass
        self.stdscr.attroff(curses.color_pair(1))

    def _get_tab_bar_height(self):
        """Calculate how many rows the tab bar uses"""
        height, width = self.stdscr.getmaxyx()
        y = 1
        x = 0

        for i, tab in enumerate(self.tabs):
            tab_text = " %s " % self._tab_title(tab)
            if x + len(tab_text) >= width:
                y += 1
                x = 0
                if y >= 4:
                    break
            x += len(tab_text) + 1

        return y

    def _draw_tabs(self):
        """Draw the tab bar"""
        height, width = self.stdscr.getmaxyx()
        y = 1
        x = 0

        for i, tab in enumerate(self.tabs):
            tab_text = " %s " % self._tab_title(tab)
            if x + len(tab_text) >= width:
                y += 1
                x = 0
                if y >= 4:
                    break

            if i == self.current_tab:
                self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            else:
                self.stdscr.attron(curses.color_pair(3))

            try:
                self.stdscr.addstr(y, x, tab_text)
            except:
                pass

            if i == self.current_tab:
                self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            else:
                self.stdscr.attroff(curses.color_pair(3))

            x += len(tab_text) + 1

    def _build_command(self):
        """Assemble the equivalent sqlmap command line from the current field values"""
        parts = ["sqlmap.py"]
        for opt in self.all_options:
            flag = opt['label'].split(',')[0].strip() if opt['label'] else ""
            if not flag:
                continue
            value = opt['value']
            if opt['type'] == 'bool':
                if value:
                    parts.append(flag)
            elif value not in (None, "") and str(value) != str(opt.get('default') or ""):
                text = str(value)
                if ' ' in text or '"' in text:
                    text = '"%s"' % text.replace('"', '\\"')
                parts.append("%s %s" % (flag, text))
        return " ".join(parts)

    def _draw_command(self):
        """Live preview of the command being built, just above the footer"""
        height, width = self.stdscr.getmaxyx()
        cmd = "$ " + self._build_command()
        if len(cmd) > width - 2:
            cmd = cmd[:width - 5] + "..."
        try:
            self.stdscr.attron(curses.color_pair(8) | curses.A_BOLD)
            self.stdscr.addstr(height - 2, 1, cmd.ljust(width - 2)[:width - 2])
            self.stdscr.attroff(curses.color_pair(8) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_footer(self):
        """Draw the footer with help text"""
        height, width = self.stdscr.getmaxyx()
        footer = " Tab/<-/-> Section   Up/Down Field   Enter/Space Edit   F2 Run   F3 Export   F4 Import   F10 Quit "

        try:
            self.stdscr.attron(curses.color_pair(1))
            self.stdscr.addstr(height - 1, 0, footer.ljust(width)[:width - 1])
            self.stdscr.attroff(curses.color_pair(1))
        except:
            pass

    def _draw_current_tab(self):
        """Draw the current tab content"""
        height, width = self.stdscr.getmaxyx()
        tab = self.tabs[self.current_tab]

        # Calculate tab bar height
        tab_bar_height = self._get_tab_bar_height()
        start_y = tab_bar_height + 1

        # Clear content area
        for y in range(start_y, height - 1):
            try:
                self.stdscr.addstr(y, 0, " " * width)
            except:
                pass

        y = start_y

        # Draw description if exists
        if tab['description']:
            desc_lines = self._wrap_text(tab['description'], width - 4)
            for line in desc_lines[:2]:  # Limit to 2 lines
                try:
                    self.stdscr.attron(curses.color_pair(5))
                    self.stdscr.addstr(y, 2, line)
                    self.stdscr.attroff(curses.color_pair(5))
                    y += 1
                except:
                    pass
            y += 1

        # Draw options (leave height-2 for the command preview, height-1 for the footer)
        visible_start = self.scroll_offset
        visible_end = visible_start + (height - y - 3)

        for i, option in enumerate(tab['options'][visible_start:visible_end], visible_start):
            if y >= height - 3:
                break

            is_selected = (i == self.current_field)

            # full-width highlight bar for the selected row
            if is_selected:
                try:
                    self.stdscr.attron(curses.color_pair(4))
                    self.stdscr.addstr(y, 0, " " * (width - 1))
                    self.stdscr.attroff(curses.color_pair(4))
                except:
                    pass

            # label
            label = option['label'][:25].ljust(25)
            label_attr = curses.color_pair(4) | curses.A_BOLD if is_selected else curses.color_pair(7)
            try:
                self.stdscr.attron(label_attr)
                self.stdscr.addstr(y, 2, label)
                self.stdscr.attroff(label_attr)
            except:
                pass

            # value (green once the user has set one, muted "(default)" otherwise)
            has_value = option['value'] not in (None, "", False)
            if option['type'] == 'bool':
                value = option['value'] if option['value'] is not None else option.get('default')
                value_str = "[x]" if value else "[ ]"
                value_attr = curses.color_pair(8) if value else curses.color_pair(5)
            elif has_value:
                value_str = str(option['value'])
                value_attr = curses.color_pair(8)
            elif option['default'] not in (None, False):
                value_str = "(%s)" % str(option['default'])
                value_attr = curses.color_pair(5)
            else:
                value_str = ""
                value_attr = curses.color_pair(5)

            if is_selected:
                value_attr = curses.color_pair(4) | curses.A_BOLD
            try:
                self.stdscr.attron(value_attr)
                self.stdscr.addstr(y, 28, value_str[:30])
                self.stdscr.attroff(value_attr)
            except:
                pass

            # help text (always shown, including on the highlighted row so it stays readable)
            if width > 65:
                help_text = option['help'][:width - 62] if option['help'] else ""
                help_attr = curses.color_pair(9) if is_selected else curses.color_pair(5)
                try:
                    self.stdscr.attron(help_attr)
                    self.stdscr.addstr(y, 60, help_text.ljust(width - 61)[:width - 61])
                    self.stdscr.attroff(help_attr)
                except:
                    pass

            y += 1

        # Draw scroll indicator
        if len(tab['options']) > visible_end - visible_start:
            try:
                self.stdscr.attron(curses.color_pair(6))
                self.stdscr.addstr(height - 3, width - 10, "[More...]")
                self.stdscr.attroff(curses.color_pair(6))
            except:
                pass

    def _wrap_text(self, text, width):
        """Wrap text to fit within width"""
        words = text.split()
        lines = []
        current_line = ""

        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line += word + " "
            else:
                if current_line:
                    lines.append(current_line.strip())
                current_line = word + " "

        if current_line:
            lines.append(current_line.strip())

        return lines

    def _edit_field(self):
        """Edit the current field"""
        tab = self.tabs[self.current_tab]
        if self.current_field >= len(tab['options']):
            return

        option = tab['options'][self.current_field]

        if option['type'] == 'bool':
            # Toggle boolean
            option['value'] = not option['value']
        else:
            # Text input (manual key loop so Esc can cancel and Enter can save)
            height, width = self.stdscr.getmaxyx()
            input_win = curses.newwin(5, width - 20, height // 2 - 2, 10)
            input_win.keypad(True)
            input_win.box()
            input_win.attron(curses.color_pair(2))
            input_win.addstr(0, 2, " Edit %s " % option['label'][:20])
            input_win.attroff(curses.color_pair(2))
            input_win.attron(curses.color_pair(5))
            input_win.addstr(3, 2, "[Enter] save   [Esc] cancel")
            input_win.attroff(curses.color_pair(5))

            buffer = str(option['value']) if option['value'] not in (None, "") else ""
            max_len = max(1, width - 34)
            curses.noecho()
            curses.curs_set(1)

            while True:
                shown = buffer[-max_len:]
                input_win.addstr(2, 2, "Value: ")
                input_win.addstr(2, 9, shown.ljust(max_len)[:max_len])
                input_win.move(2, 9 + len(shown))
                input_win.refresh()

                ch = input_win.getch()
                if ch == 27:                                    # Esc -> cancel, keep old value
                    buffer = None
                    break
                elif ch in (curses.KEY_ENTER, 10, 13):          # Enter -> commit
                    break
                elif ch in (curses.KEY_BACKSPACE, 127, 8):
                    buffer = buffer[:-1]
                elif 32 <= ch <= 126:
                    buffer += chr(ch)

            curses.curs_set(0)

            if buffer is not None:
                if option['type'] == 'int':
                    try:
                        option['value'] = int(buffer) if buffer else None
                    except ValueError:
                        option['value'] = None
                elif option['type'] == 'float':
                    try:
                        option['value'] = float(buffer) if buffer else None
                    except ValueError:
                        option['value'] = None
                else:
                    option['value'] = buffer if buffer else None

            input_win.clear()
            input_win.refresh()
            del input_win

    def _export_config(self):
        """Export current configuration to a file"""
        height, width = self.stdscr.getmaxyx()

        # Create input window
        input_win = curses.newwin(5, width - 20, height // 2 - 2, 10)
        input_win.box()
        input_win.attron(curses.color_pair(2))
        input_win.addstr(0, 2, " Export Configuration ")
        input_win.attroff(curses.color_pair(2))
        input_win.addstr(2, 2, "File:")
        input_win.refresh()

        # Get input
        curses.echo()
        curses.curs_set(1)

        try:
            filename = input_win.getstr(2, 8, width - 32).decode('utf-8').strip()

            if filename:
                # Collect all field values
                config = {}
                for tab in self.tabs:
                    for option in tab['options']:
                        dest = option['dest']
                        value = option['value'] if option['value'] is not None else option.get('default')

                        if option['type'] == 'bool':
                            config[dest] = bool(value)
                        elif option['type'] == 'int':
                            config[dest] = int(value) if value else None
                        elif option['type'] == 'float':
                            config[dest] = float(value) if value else None
                        else:
                            config[dest] = value

                # Set defaults for unset options
                for field in self.all_options:
                    if field['dest'] not in config or config[field['dest']] is None:
                        config[field['dest']] = defaults.get(field['dest'], None)

                # Save config
                try:
                    saveConfig(config, filename)

                    # Show success message
                    input_win.clear()
                    input_win.box()
                    input_win.attron(curses.color_pair(5))
                    input_win.addstr(0, 2, " Export Successful ")
                    input_win.attroff(curses.color_pair(5))
                    input_win.addstr(2, 2, "Configuration exported to:")
                    input_win.addstr(3, 2, filename[:width - 26])
                    input_win.refresh()
                    curses.napms(2000)
                except Exception as ex:
                    # Show error message
                    input_win.clear()
                    input_win.box()
                    input_win.attron(curses.color_pair(6))
                    input_win.addstr(0, 2, " Export Failed ")
                    input_win.attroff(curses.color_pair(6))
                    input_win.addstr(2, 2, str(getSafeExString(ex))[:width - 26])
                    input_win.refresh()
                    curses.napms(2000)
        except:
            pass

        curses.noecho()
        curses.curs_set(0)

        # Clear input window
        input_win.clear()
        input_win.refresh()
        del input_win

    def _import_config(self):
        """Import configuration from a file"""
        height, width = self.stdscr.getmaxyx()

        # Create input window
        input_win = curses.newwin(5, width - 20, height // 2 - 2, 10)
        input_win.box()
        input_win.attron(curses.color_pair(2))
        input_win.addstr(0, 2, " Import Configuration ")
        input_win.attroff(curses.color_pair(2))
        input_win.addstr(2, 2, "File:")
        input_win.refresh()

        # Get input
        curses.echo()
        curses.curs_set(1)

        try:
            filename = input_win.getstr(2, 8, width - 32).decode('utf-8').strip()

            if filename and os.path.isfile(filename):
                try:
                    # Read config file
                    config = _configparser.ConfigParser()
                    config.read(filename)

                    imported_count = 0

                    # Load values into fields
                    for tab in self.tabs:
                        for option in tab['options']:
                            dest = option['dest']

                            # Search for option in all sections
                            for section in config.sections():
                                if config.has_option(section, dest):
                                    value = config.get(section, dest)

                                    # Convert based on type
                                    if option['type'] == 'bool':
                                        option['value'] = value.lower() in ('true', '1', 'yes', 'on')
                                    elif option['type'] == 'int':
                                        try:
                                            option['value'] = int(value) if value else None
                                        except ValueError:
                                            option['value'] = None
                                    elif option['type'] == 'float':
                                        try:
                                            option['value'] = float(value) if value else None
                                        except ValueError:
                                            option['value'] = None
                                    else:
                                        option['value'] = value if value else None

                                    imported_count += 1
                                    break

                    # Show success message
                    input_win.clear()
                    input_win.box()
                    input_win.attron(curses.color_pair(5))
                    input_win.addstr(0, 2, " Import Successful ")
                    input_win.attroff(curses.color_pair(5))
                    input_win.addstr(2, 2, "Imported %d options from:" % imported_count)
                    input_win.addstr(3, 2, filename[:width - 26])
                    input_win.refresh()
                    curses.napms(2000)

                except Exception as ex:
                    # Show error message
                    input_win.clear()
                    input_win.box()
                    input_win.attron(curses.color_pair(6))
                    input_win.addstr(0, 2, " Import Failed ")
                    input_win.attroff(curses.color_pair(6))
                    input_win.addstr(2, 2, str(getSafeExString(ex))[:width - 26])
                    input_win.refresh()
                    curses.napms(2000)
            elif filename:
                # File not found
                input_win.clear()
                input_win.box()
                input_win.attron(curses.color_pair(6))
                input_win.addstr(0, 2, " File Not Found ")
                input_win.attroff(curses.color_pair(6))
                input_win.addstr(2, 2, "File does not exist:")
                input_win.addstr(3, 2, filename[:width - 26])
                input_win.refresh()
                curses.napms(2000)
        except:
            pass

        curses.noecho()
        curses.curs_set(0)

        # Clear input window
        input_win.clear()
        input_win.refresh()
        del input_win

    def _run_sqlmap(self):
        """Run sqlmap with current configuration"""
        config = {}

        # Collect all field values
        for tab in self.tabs:
            for option in tab['options']:
                dest = option['dest']
                value = option['value'] if option['value'] is not None else option.get('default')

                if option['type'] == 'bool':
                    config[dest] = bool(value)
                elif option['type'] == 'int':
                    config[dest] = int(value) if value else None
                elif option['type'] == 'float':
                    config[dest] = float(value) if value else None
                else:
                    config[dest] = value

        # Set defaults for unset options
        for field in self.all_options:
            if field['dest'] not in config or config[field['dest']] is None:
                config[field['dest']] = defaults.get(field['dest'], None)

        # Create temp config file
        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
        os.close(handle)

        saveConfig(config, configFile)

        # Show console
        self._show_console(configFile)

    def _show_console(self, configFile):
        """Show console output from sqlmap"""
        height, width = self.stdscr.getmaxyx()

        # Create console window
        console_win = curses.newwin(height - 4, width - 4, 2, 2)
        console_win.box()
        console_win.attron(curses.color_pair(2))
        console_win.addstr(0, 2, " sqlmap Console - Press Q to close ")
        console_win.attroff(curses.color_pair(2))
        console_win.refresh()

        # Create output area
        output_win = console_win.derwin(height - 8, width - 8, 2, 2)
        output_win.scrollok(True)
        output_win.idlok(True)

        # Start sqlmap process
        try:
            process = subprocess.Popen(
                [sys.executable or "python", os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap.py"), "-c", configFile],
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                bufsize=1,
                close_fds=not IS_WIN
            )

            if not IS_WIN:
                # Make it non-blocking
                import fcntl
                flags = fcntl.fcntl(process.stdout, fcntl.F_GETFL)
                fcntl.fcntl(process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            output_win.nodelay(True)
            console_win.nodelay(True)

            lines = []
            current_line = ""

            while True:
                # Check for user input
                try:
                    key = console_win.getch()
                    if key in (ord('q'), ord('Q')):
                        # Kill process
                        process.terminate()
                        break
                    elif key == curses.KEY_ENTER or key == 10:
                        # Send newline to process
                        if process.poll() is None:
                            try:
                                process.stdin.write(b'\n')
                                process.stdin.flush()
                            except:
                                pass
                except:
                    pass

                # Read output
                try:
                    chunk = process.stdout.read(1024)
                    if chunk:
                        current_line += chunk.decode('utf-8', errors='ignore')

                        # Split into lines
                        while '\n' in current_line:
                            line, current_line = current_line.split('\n', 1)
                            lines.append(line)

                            # Keep only last N lines
                            if len(lines) > 1000:
                                lines = lines[-1000:]

                            # Display lines
                            output_win.clear()
                            start_line = max(0, len(lines) - (height - 10))
                            for i, l in enumerate(lines[start_line:]):
                                try:
                                    output_win.addstr(i, 0, l[:width-10])
                                except:
                                    pass
                            output_win.refresh()
                            console_win.refresh()
                except:
                    pass

                # Check if process ended
                if process.poll() is not None:
                    # Read remaining output
                    try:
                        remaining = process.stdout.read()
                        if remaining:
                            current_line += remaining.decode('utf-8', errors='ignore')
                            for line in current_line.split('\n'):
                                if line:
                                    lines.append(line)
                    except:
                        pass

                    # Display final output
                    output_win.clear()
                    start_line = max(0, len(lines) - (height - 10))
                    for i, l in enumerate(lines[start_line:]):
                        try:
                            output_win.addstr(i, 0, l[:width-10])
                        except:
                            pass

                    output_win.addstr(height - 9, 0, "--- Process finished. Press Q to close ---")
                    output_win.refresh()
                    console_win.refresh()

                    # Wait for Q
                    console_win.nodelay(False)
                    while True:
                        key = console_win.getch()
                        if key in (ord('q'), ord('Q')):
                            break

                    break

                # Small delay
                curses.napms(50)

        except Exception as ex:
            output_win.addstr(0, 0, "Error: %s" % getSafeExString(ex))
            output_win.refresh()
            console_win.nodelay(False)
            console_win.getch()

        finally:
            # Clean up
            try:
                os.unlink(configFile)
            except:
                pass

            console_win.nodelay(False)
            output_win.nodelay(False)
            del output_win
            del console_win

    def run(self):
        """Main UI loop"""
        while True:
            self.stdscr.clear()

            # Draw UI
            self._draw_header()
            self._draw_tabs()
            self._draw_current_tab()
            self._draw_command()
            self._draw_footer()

            self.stdscr.refresh()

            # Get input
            key = self.stdscr.getch()

            tab = self.tabs[self.current_tab]

            # Handle input
            if key == curses.KEY_F10:  # F10 quits; Esc intentionally does NOT (it only cancels field edits)
                break
            elif key == ord('\t') or key == curses.KEY_RIGHT:  # Tab or Right arrow
                self.current_tab = (self.current_tab + 1) % len(self.tabs)
                self.current_field = 0
                self.scroll_offset = 0
            elif key == curses.KEY_LEFT:  # Left arrow
                self.current_tab = (self.current_tab - 1) % len(self.tabs)
                self.current_field = 0
                self.scroll_offset = 0
            elif key == curses.KEY_UP:  # Up arrow
                if self.current_field > 0:
                    self.current_field -= 1
                    # Adjust scroll if needed
                    if self.current_field < self.scroll_offset:
                        self.scroll_offset = self.current_field
            elif key == curses.KEY_DOWN:  # Down arrow
                if self.current_field < len(tab['options']) - 1:
                    self.current_field += 1
                    # Adjust scroll if needed
                    height, width = self.stdscr.getmaxyx()
                    visible_lines = height - 8
                    if self.current_field >= self.scroll_offset + visible_lines:
                        self.scroll_offset = self.current_field - visible_lines + 1
            elif key == curses.KEY_ENTER or key == 10 or key == 13:  # Enter
                self._edit_field()
            elif key == curses.KEY_F2:  # F2 to run
                self._run_sqlmap()
            elif key == curses.KEY_F3:  # F3 to export
                self._export_config()
            elif key == curses.KEY_F4:  # F4 to import
                self._import_config()
            elif key == ord(' '):  # Space for boolean toggle
                option = tab['options'][self.current_field]
                if option['type'] == 'bool':
                    option['value'] = not option['value']

def runTui(parser):
    """Main entry point for ncurses TUI"""
    # Check if ncurses is available
    if curses is None:
        raise SqlmapMissingDependence("missing 'curses' module (optional Python module). Use a Python build that includes curses/ncurses, or install the platform-provided equivalent (e.g. for Windows: pip install windows-curses)")
    # ncurses waits ESCDELAY ms (default 1000) after Esc to disambiguate escape sequences, which
    # makes Esc feel like it hangs for ~1s; shrink it so Esc reacts immediately
    os.environ.setdefault("ESCDELAY", "25")
    try:
        # Initialize and run
        def main(stdscr):
            if hasattr(curses, "set_escdelay"):
                try:
                    curses.set_escdelay(25)
                except curses.error:
                    pass
            ui = NcursesUI(stdscr, parser)
            ui.run()

        curses.wrapper(main)

    except Exception as ex:
        errMsg = "unable to create ncurses UI ('%s')" % getSafeExString(ex)
        raise SqlmapSystemException(errMsg)
