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
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Header
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Active tab
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Inactive tab
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Selected field
        curses.init_pair(5, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Help text
        curses.init_pair(6, curses.COLOR_RED, curses.COLOR_BLACK)     # Error/Important
        curses.init_pair(7, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Label

        # Setup curses
        curses.curs_set(1)
        self.stdscr.keypad(1)

        # Parse option groups
        self._parse_options()

    def _parse_options(self):
        """Parse command line options into tabs and fields"""
        for group in self.parser.option_groups:
            tab_data = {
                'title': group.title,
                'description': group.get_description() if hasattr(group, 'get_description') and group.get_description() else "",
                'options': []
            }

            for option in group.option_list:
                field_data = {
                    'dest': option.dest,
                    'label': self._format_option_strings(option),
                    'help': option.help if option.help else "",
                    'type': option.type if hasattr(option, 'type') and option.type else 'bool',
                    'value': '',
                    'default': defaults.get(option.dest) if defaults.get(option.dest) else None
                }
                tab_data['options'].append(field_data)
                self.fields[(group.title, option.dest)] = field_data

            self.tabs.append(tab_data)

    def _format_option_strings(self, option):
        """Format option strings for display"""
        parts = []
        if hasattr(option, '_short_opts') and option._short_opts:
            parts.extend(option._short_opts)
        if hasattr(option, '_long_opts') and option._long_opts:
            parts.extend(option._long_opts)
        return ', '.join(parts)

    def _draw_header(self):
        """Draw the header bar"""
        height, width = self.stdscr.getmaxyx()
        header = " sqlmap - ncurses TUI "
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, header.center(width))
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

    def _get_tab_bar_height(self):
        """Calculate how many rows the tab bar uses"""
        height, width = self.stdscr.getmaxyx()
        y = 1
        x = 0

        for i, tab in enumerate(self.tabs):
            tab_text = " %s " % tab['title']

            # Check if tab exceeds width, wrap to next line
            if x + len(tab_text) >= width:
                y += 1
                x = 0
                # Stop if we've used too many lines
                if y >= 3:
                    break

            x += len(tab_text) + 1

        return y

    def _draw_tabs(self):
        """Draw the tab bar"""
        height, width = self.stdscr.getmaxyx()
        y = 1
        x = 0

        for i, tab in enumerate(self.tabs):
            tab_text = " %s " % tab['title']

            # Check if tab exceeds width, wrap to next line
            if x + len(tab_text) >= width:
                y += 1
                x = 0
                # Stop if we've used too many lines
                if y >= 3:
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

    def _draw_footer(self):
        """Draw the footer with help text"""
        height, width = self.stdscr.getmaxyx()
        footer = " [Tab] Next | [Arrows] Navigate | [Enter] Edit | [F2] Run | [F3] Export | [F4] Import | [F10] Quit "

        try:
            self.stdscr.attron(curses.color_pair(1))
            self.stdscr.addstr(height - 1, 0, footer.ljust(width))
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

        # Draw options
        visible_start = self.scroll_offset
        visible_end = visible_start + (height - y - 2)

        for i, option in enumerate(tab['options'][visible_start:visible_end], visible_start):
            if y >= height - 2:
                break

            is_selected = (i == self.current_field)

            # Draw label
            label = option['label'][:25].ljust(25)
            try:
                if is_selected:
                    self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
                else:
                    self.stdscr.attron(curses.color_pair(7))

                self.stdscr.addstr(y, 2, label)

                if is_selected:
                    self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
                else:
                    self.stdscr.attroff(curses.color_pair(7))
            except:
                pass

            # Draw value
            value_str = ""
            if option['type'] == 'bool':
                value = option['value'] if option['value'] is not None else option.get('default')
                value_str = "[X]" if value else "[ ]"
            else:
                value_str = str(option['value']) if option['value'] else ""
                if option['default'] and not option['value']:
                    value_str = "(%s)" % str(option['default'])

            value_str = value_str[:30]

            try:
                if is_selected:
                    self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
                self.stdscr.addstr(y, 28, value_str)
                if is_selected:
                    self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
            except:
                pass

            # Draw help text
            if width > 65:
                help_text = option['help'][:width-62] if option['help'] else ""
                try:
                    self.stdscr.attron(curses.color_pair(5))
                    self.stdscr.addstr(y, 60, help_text)
                    self.stdscr.attroff(curses.color_pair(5))
                except:
                    pass

            y += 1

        # Draw scroll indicator
        if len(tab['options']) > visible_end - visible_start:
            try:
                self.stdscr.attron(curses.color_pair(6))
                self.stdscr.addstr(height - 2, width - 10, "[More...]")
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
            # Text input
            height, width = self.stdscr.getmaxyx()

            # Create input window
            input_win = curses.newwin(5, width - 20, height // 2 - 2, 10)
            input_win.box()
            input_win.attron(curses.color_pair(2))
            input_win.addstr(0, 2, " Edit %s " % option['label'][:20])
            input_win.attroff(curses.color_pair(2))
            input_win.addstr(2, 2, "Value:")
            input_win.refresh()

            # Get input
            curses.echo()
            curses.curs_set(1)

            # Pre-fill with existing value
            current_value = str(option['value']) if option['value'] else ""
            input_win.addstr(2, 9, current_value)
            input_win.move(2, 9)

            try:
                new_value = input_win.getstr(2, 9, width - 32).decode('utf-8')

                # Validate and convert based on type
                if option['type'] == 'int':
                    try:
                        option['value'] = int(new_value) if new_value else None
                    except ValueError:
                        option['value'] = None
                elif option['type'] == 'float':
                    try:
                        option['value'] = float(new_value) if new_value else None
                    except ValueError:
                        option['value'] = None
                else:
                    option['value'] = new_value if new_value else None
            except:
                pass

            curses.noecho()
            curses.curs_set(0)

            # Clear input window
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
                for option in self.parser.option_list:
                    if option.dest not in config or config[option.dest] is None:
                        config[option.dest] = defaults.get(option.dest, None)

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
        for option in self.parser.option_list:
            if option.dest not in config or config[option.dest] is None:
                config[option.dest] = defaults.get(option.dest, None)

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
            self._draw_footer()

            self.stdscr.refresh()

            # Get input
            key = self.stdscr.getch()

            tab = self.tabs[self.current_tab]

            # Handle input
            if key == curses.KEY_F10 or key == 27:  # F10 or ESC
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
    try:
        # Initialize and run
        def main(stdscr):
            ui = NcursesUI(stdscr, parser)
            ui.run()

        curses.wrapper(main)

    except Exception as ex:
        errMsg = "unable to create ncurses UI ('%s')" % getSafeExString(ex)
        raise SqlmapSystemException(errMsg)
