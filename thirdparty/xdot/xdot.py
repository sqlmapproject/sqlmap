#!/usr/bin/env python
#
# Copyright 2008 Jose Fonseca
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

'''Visualize dot graphs via the xdot format.'''

__author__ = "Jose Fonseca et al"


import os
import sys
import subprocess
import math
import colorsys
import time
import re
import optparse

import gobject
import gtk
import gtk.gdk
import gtk.keysyms
import cairo
import pango
import pangocairo


# See http://www.graphviz.org/pub/scm/graphviz-cairo/plugin/cairo/gvrender_cairo.c

# For pygtk inspiration and guidance see:
# - http://mirageiv.berlios.de/
# - http://comix.sourceforge.net/


class Pen:
    """Store pen attributes."""

    def __init__(self):
        # set default attributes
        self.color = (0.0, 0.0, 0.0, 1.0)
        self.fillcolor = (0.0, 0.0, 0.0, 1.0)
        self.linewidth = 1.0
        self.fontsize = 14.0
        self.fontname = "Times-Roman"
        self.dash = ()

    def copy(self):
        """Create a copy of this pen."""
        pen = Pen()
        pen.__dict__ = self.__dict__.copy()
        return pen

    def highlighted(self):
        pen = self.copy()
        pen.color = (1, 0, 0, 1)
        pen.fillcolor = (1, .8, .8, 1)
        return pen


class Shape:
    """Abstract base class for all the drawing shapes."""

    def __init__(self):
        pass

    def draw(self, cr, highlight=False):
        """Draw this shape with the given cairo context"""
        raise NotImplementedError

    def select_pen(self, highlight):
        if highlight:
            if not hasattr(self, 'highlight_pen'):
                self.highlight_pen = self.pen.highlighted()
            return self.highlight_pen
        else:
            return self.pen

    def search_text(self, regexp):
        return False


class TextShape(Shape):

    LEFT, CENTER, RIGHT = -1, 0, 1

    def __init__(self, pen, x, y, j, w, t):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.x = x
        self.y = y
        self.j = j
        self.w = w
        self.t = t

    def draw(self, cr, highlight=False):

        try:
            layout = self.layout
        except AttributeError:
            layout = cr.create_layout()

            # set font options
            # see http://lists.freedesktop.org/archives/cairo/2007-February/009688.html
            context = layout.get_context()
            fo = cairo.FontOptions()
            fo.set_antialias(cairo.ANTIALIAS_DEFAULT)
            fo.set_hint_style(cairo.HINT_STYLE_NONE)
            fo.set_hint_metrics(cairo.HINT_METRICS_OFF)
            try:
                pangocairo.context_set_font_options(context, fo)
            except TypeError:
                # XXX: Some broken pangocairo bindings show the error
                # 'TypeError: font_options must be a cairo.FontOptions or None'
                pass

            # set font
            font = pango.FontDescription()
            font.set_family(self.pen.fontname)
            font.set_absolute_size(self.pen.fontsize*pango.SCALE)
            layout.set_font_description(font)

            # set text
            layout.set_text(self.t)

            # cache it
            self.layout = layout
        else:
            cr.update_layout(layout)

        descent = 2 # XXX get descender from font metrics

        width, height = layout.get_size()
        width = float(width)/pango.SCALE
        height = float(height)/pango.SCALE
        # we know the width that dot thinks this text should have
        # we do not necessarily have a font with the same metrics
        # scale it so that the text fits inside its box
        if width > self.w:
            f = self.w / width
            width = self.w # equivalent to width *= f
            height *= f
            descent *= f
        else:
            f = 1.0

        if self.j == self.LEFT:
            x = self.x
        elif self.j == self.CENTER:
            x = self.x - 0.5*width
        elif self.j == self.RIGHT:
            x = self.x - width
        else:
            assert 0

        y = self.y - height + descent

        cr.move_to(x, y)

        cr.save()
        cr.scale(f, f)
        cr.set_source_rgba(*self.select_pen(highlight).color)
        cr.show_layout(layout)
        cr.restore()

        if 0: # DEBUG
            # show where dot thinks the text should appear
            cr.set_source_rgba(1, 0, 0, .9)
            if self.j == self.LEFT:
                x = self.x
            elif self.j == self.CENTER:
                x = self.x - 0.5*self.w
            elif self.j == self.RIGHT:
                x = self.x - self.w
            cr.move_to(x, self.y)
            cr.line_to(x+self.w, self.y)
            cr.stroke()

    def search_text(self, regexp):
        return regexp.search(self.t) is not None


class ImageShape(Shape):

    def __init__(self, pen, x0, y0, w, h, path):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.x0 = x0
        self.y0 = y0
        self.w = w
        self.h = h
        self.path = path

    def draw(self, cr, highlight=False):
        cr2 = gtk.gdk.CairoContext(cr)
        pixbuf = gtk.gdk.pixbuf_new_from_file(self.path)
        sx = float(self.w)/float(pixbuf.get_width())
        sy = float(self.h)/float(pixbuf.get_height())
        cr.save()
        cr.translate(self.x0, self.y0 - self.h)
        cr.scale(sx, sy)
        cr2.set_source_pixbuf(pixbuf, 0, 0)
        cr2.paint()
        cr.restore()


class EllipseShape(Shape):

    def __init__(self, pen, x0, y0, w, h, filled=False):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.x0 = x0
        self.y0 = y0
        self.w = w
        self.h = h
        self.filled = filled

    def draw(self, cr, highlight=False):
        cr.save()
        cr.translate(self.x0, self.y0)
        cr.scale(self.w, self.h)
        cr.move_to(1.0, 0.0)
        cr.arc(0.0, 0.0, 1.0, 0, 2.0*math.pi)
        cr.restore()
        pen = self.select_pen(highlight)
        if self.filled:
            cr.set_source_rgba(*pen.fillcolor)
            cr.fill()
        else:
            cr.set_dash(pen.dash)
            cr.set_line_width(pen.linewidth)
            cr.set_source_rgba(*pen.color)
            cr.stroke()


class PolygonShape(Shape):

    def __init__(self, pen, points, filled=False):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.points = points
        self.filled = filled

    def draw(self, cr, highlight=False):
        x0, y0 = self.points[-1]
        cr.move_to(x0, y0)
        for x, y in self.points:
            cr.line_to(x, y)
        cr.close_path()
        pen = self.select_pen(highlight)
        if self.filled:
            cr.set_source_rgba(*pen.fillcolor)
            cr.fill_preserve()
            cr.fill()
        else:
            cr.set_dash(pen.dash)
            cr.set_line_width(pen.linewidth)
            cr.set_source_rgba(*pen.color)
            cr.stroke()


class LineShape(Shape):

    def __init__(self, pen, points):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.points = points

    def draw(self, cr, highlight=False):
        x0, y0 = self.points[0]
        cr.move_to(x0, y0)
        for x1, y1 in self.points[1:]:
            cr.line_to(x1, y1)
        pen = self.select_pen(highlight)
        cr.set_dash(pen.dash)
        cr.set_line_width(pen.linewidth)
        cr.set_source_rgba(*pen.color)
        cr.stroke()


class BezierShape(Shape):

    def __init__(self, pen, points, filled=False):
        Shape.__init__(self)
        self.pen = pen.copy()
        self.points = points
        self.filled = filled

    def draw(self, cr, highlight=False):
        x0, y0 = self.points[0]
        cr.move_to(x0, y0)
        for i in xrange(1, len(self.points), 3):
            x1, y1 = self.points[i]
            x2, y2 = self.points[i + 1]
            x3, y3 = self.points[i + 2]
            cr.curve_to(x1, y1, x2, y2, x3, y3)
        pen = self.select_pen(highlight)
        if self.filled:
            cr.set_source_rgba(*pen.fillcolor)
            cr.fill_preserve()
            cr.fill()
        else:
            cr.set_dash(pen.dash)
            cr.set_line_width(pen.linewidth)
            cr.set_source_rgba(*pen.color)
            cr.stroke()


class CompoundShape(Shape):

    def __init__(self, shapes):
        Shape.__init__(self)
        self.shapes = shapes

    def draw(self, cr, highlight=False):
        for shape in self.shapes:
            shape.draw(cr, highlight=highlight)

    def search_text(self, regexp):
        for shape in self.shapes:
            if shape.search_text(regexp):
                return True
        return False


class Url(object):

    def __init__(self, item, url, highlight=None):
        self.item = item
        self.url = url
        if highlight is None:
            highlight = set([item])
        self.highlight = highlight


class Jump(object):

    def __init__(self, item, x, y, highlight=None):
        self.item = item
        self.x = x
        self.y = y
        if highlight is None:
            highlight = set([item])
        self.highlight = highlight


class Element(CompoundShape):
    """Base class for graph nodes and edges."""

    def __init__(self, shapes):
        CompoundShape.__init__(self, shapes)

    def is_inside(self, x, y):
        return False

    def get_url(self, x, y):
        return None

    def get_jump(self, x, y):
        return None


class Node(Element):

    def __init__(self, id, x, y, w, h, shapes, url):
        Element.__init__(self, shapes)

        self.id = id
        self.x = x
        self.y = y

        self.x1 = x - 0.5*w
        self.y1 = y - 0.5*h
        self.x2 = x + 0.5*w
        self.y2 = y + 0.5*h

        self.url = url

    def is_inside(self, x, y):
        return self.x1 <= x and x <= self.x2 and self.y1 <= y and y <= self.y2

    def get_url(self, x, y):
        if self.url is None:
            return None
        if self.is_inside(x, y):
            return Url(self, self.url)
        return None

    def get_jump(self, x, y):
        if self.is_inside(x, y):
            return Jump(self, self.x, self.y)
        return None

    def __repr__(self):
        return "<Node %s>" % self.id


def square_distance(x1, y1, x2, y2):
    deltax = x2 - x1
    deltay = y2 - y1
    return deltax*deltax + deltay*deltay


class Edge(Element):

    def __init__(self, src, dst, points, shapes):
        Element.__init__(self, shapes)
        self.src = src
        self.dst = dst
        self.points = points

    RADIUS = 10

    def is_inside_begin(self, x, y):
        return square_distance(x, y, *self.points[0]) <= self.RADIUS*self.RADIUS

    def is_inside_end(self, x, y):
        return square_distance(x, y, *self.points[-1]) <= self.RADIUS*self.RADIUS

    def is_inside(self, x, y):
        if self.is_inside_begin(x, y):
            return True
        if self.is_inside_end(x, y):
            return True
        return False

    def get_jump(self, x, y):
        if self.is_inside_begin(x, y):
            return Jump(self, self.dst.x, self.dst.y, highlight=set([self, self.dst]))
        if self.is_inside_end(x, y):
            return Jump(self, self.src.x, self.src.y, highlight=set([self, self.src]))
        return None

    def __repr__(self):
        return "<Edge %s -> %s>" % (self.src, self.dst)


class Graph(Shape):

    def __init__(self, width=1, height=1, shapes=(), nodes=(), edges=()):
        Shape.__init__(self)

        self.width = width
        self.height = height
        self.shapes = shapes
        self.nodes = nodes
        self.edges = edges

    def get_size(self):
        return self.width, self.height

    def draw(self, cr, highlight_items=None):
        if highlight_items is None:
            highlight_items = ()
        cr.set_source_rgba(0.0, 0.0, 0.0, 1.0)

        cr.set_line_cap(cairo.LINE_CAP_BUTT)
        cr.set_line_join(cairo.LINE_JOIN_MITER)

        for shape in self.shapes:
            shape.draw(cr)
        for edge in self.edges:
            edge.draw(cr, highlight=(edge in highlight_items))
        for node in self.nodes:
            node.draw(cr, highlight=(node in highlight_items))

    def get_element(self, x, y):
        for node in self.nodes:
            if node.is_inside(x, y):
                return node
        for edge in self.edges:
            if edge.is_inside(x, y):
                return edge

    def get_url(self, x, y):
        for node in self.nodes:
            url = node.get_url(x, y)
            if url is not None:
                return url
        return None

    def get_jump(self, x, y):
        for edge in self.edges:
            jump = edge.get_jump(x, y)
            if jump is not None:
                return jump
        for node in self.nodes:
            jump = node.get_jump(x, y)
            if jump is not None:
                return jump
        return None


BOLD = 1
ITALIC = 2
UNDERLINE = 4
SUPERSCRIPT = 8
SUBSCRIPT = 16
STRIKE_THROUGH = 32


class XDotAttrParser:
    """Parser for xdot drawing attributes.
    See also:
    - http://www.graphviz.org/doc/info/output.html#d:xdot
    """

    def __init__(self, parser, buf):
        self.parser = parser
        self.buf = buf
        self.pos = 0

        self.pen = Pen()
        self.shapes = []

    def __nonzero__(self):
        return self.pos < len(self.buf)

    def read_code(self):
        pos = self.buf.find(" ", self.pos)
        res = self.buf[self.pos:pos]
        self.pos = pos + 1
        while self.pos < len(self.buf) and self.buf[self.pos].isspace():
            self.pos += 1
        return res

    def read_int(self):
        return int(self.read_code())

    def read_float(self):
        return float(self.read_code())

    def read_point(self):
        x = self.read_float()
        y = self.read_float()
        return self.transform(x, y)

    def read_text(self):
        num = self.read_int()
        pos = self.buf.find("-", self.pos) + 1
        self.pos = pos + num
        res = self.buf[pos:self.pos]
        while self.pos < len(self.buf) and self.buf[self.pos].isspace():
            self.pos += 1
        return res

    def read_polygon(self):
        n = self.read_int()
        p = []
        for i in range(n):
            x, y = self.read_point()
            p.append((x, y))
        return p

    def read_color(self):
        # See http://www.graphviz.org/doc/info/attrs.html#k:color
        c = self.read_text()
        c1 = c[:1]
        if c1 == '#':
            hex2float = lambda h: float(int(h, 16)/255.0)
            r = hex2float(c[1:3])
            g = hex2float(c[3:5])
            b = hex2float(c[5:7])
            try:
                a = hex2float(c[7:9])
            except (IndexError, ValueError):
                a = 1.0
            return r, g, b, a
        elif c1.isdigit() or c1 == ".":
            # "H,S,V" or "H S V" or "H, S, V" or any other variation
            h, s, v = map(float, c.replace(",", " ").split())
            r, g, b = colorsys.hsv_to_rgb(h, s, v)
            a = 1.0
            return r, g, b, a
        elif c1 == "[":
            sys.stderr.write('warning: color gradients not supported yet\n')
            return None
        else:
            return self.lookup_color(c)

    def lookup_color(self, c):
        try:
            color = gtk.gdk.color_parse(c)
        except ValueError:
            pass
        else:
            s = 1.0/65535.0
            r = color.red*s
            g = color.green*s
            b = color.blue*s
            a = 1.0
            return r, g, b, a

        try:
            dummy, scheme, index = c.split('/')
            r, g, b = brewer_colors[scheme][int(index)]
        except (ValueError, KeyError):
            pass
        else:
            s = 1.0/255.0
            r = r*s
            g = g*s
            b = b*s
            a = 1.0
            return r, g, b, a

        sys.stderr.write("warning: unknown color '%s'\n" % c)
        return None

    def parse(self):
        s = self

        while s:
            op = s.read_code()
            if op == "c":
                color = s.read_color()
                if color is not None:
                    self.handle_color(color, filled=False)
            elif op == "C":
                color = s.read_color()
                if color is not None:
                    self.handle_color(color, filled=True)
            elif op == "S":
                # http://www.graphviz.org/doc/info/attrs.html#k:style
                style = s.read_text()
                if style.startswith("setlinewidth("):
                    lw = style.split("(")[1].split(")")[0]
                    lw = float(lw)
                    self.handle_linewidth(lw)
                elif style in ("solid", "dashed", "dotted"):
                    self.handle_linestyle(style)
            elif op == "F":
                size = s.read_float()
                name = s.read_text()
                self.handle_font(size, name)
            elif op == "T":
                x, y = s.read_point()
                j = s.read_int()
                w = s.read_float()
                t = s.read_text()
                self.handle_text(x, y, j, w, t)
            elif op == "t":
                f = s.read_int()
                self.handle_font_characteristics(f)
            elif op == "E":
                x0, y0 = s.read_point()
                w = s.read_float()
                h = s.read_float()
                self.handle_ellipse(x0, y0, w, h, filled=True)
            elif op == "e":
                x0, y0 = s.read_point()
                w = s.read_float()
                h = s.read_float()
                self.handle_ellipse(x0, y0, w, h, filled=False)
            elif op == "L":
                points = self.read_polygon()
                self.handle_line(points)
            elif op == "B":
                points = self.read_polygon()
                self.handle_bezier(points, filled=False)
            elif op == "b":
                points = self.read_polygon()
                self.handle_bezier(points, filled=True)
            elif op == "P":
                points = self.read_polygon()
                self.handle_polygon(points, filled=True)
            elif op == "p":
                points = self.read_polygon()
                self.handle_polygon(points, filled=False)
            elif op == "I":
                x0, y0 = s.read_point()
                w = s.read_float()
                h = s.read_float()
                path = s.read_text()
                self.handle_image(x0, y0, w, h, path)
            else:
                sys.stderr.write("error: unknown xdot opcode '%s'\n" % op)
                sys.exit(1)

        return self.shapes

    def transform(self, x, y):
        return self.parser.transform(x, y)

    def handle_color(self, color, filled=False):
        if filled:
            self.pen.fillcolor = color
        else:
            self.pen.color = color

    def handle_linewidth(self, linewidth):
        self.pen.linewidth = linewidth

    def handle_linestyle(self, style):
        if style == "solid":
            self.pen.dash = ()
        elif style == "dashed":
            self.pen.dash = (6, )       # 6pt on, 6pt off
        elif style == "dotted":
            self.pen.dash = (2, 4)       # 2pt on, 4pt off

    def handle_font(self, size, name):
        self.pen.fontsize = size
        self.pen.fontname = name

    def handle_font_characteristics(self, flags):
        # TODO
        if flags != 0:
            sys.stderr.write("warning: font characteristics not supported yet\n" % op)

    def handle_text(self, x, y, j, w, t):
        self.shapes.append(TextShape(self.pen, x, y, j, w, t))

    def handle_ellipse(self, x0, y0, w, h, filled=False):
        if filled:
            # xdot uses this to mean "draw a filled shape with an outline"
            self.shapes.append(EllipseShape(self.pen, x0, y0, w, h, filled=True))
        self.shapes.append(EllipseShape(self.pen, x0, y0, w, h))

    def handle_image(self, x0, y0, w, h, path):
        self.shapes.append(ImageShape(self.pen, x0, y0, w, h, path))

    def handle_line(self, points):
        self.shapes.append(LineShape(self.pen, points))

    def handle_bezier(self, points, filled=False):
        if filled:
            # xdot uses this to mean "draw a filled shape with an outline"
            self.shapes.append(BezierShape(self.pen, points, filled=True))
        self.shapes.append(BezierShape(self.pen, points))

    def handle_polygon(self, points, filled=False):
        if filled:
            # xdot uses this to mean "draw a filled shape with an outline"
            self.shapes.append(PolygonShape(self.pen, points, filled=True))
        self.shapes.append(PolygonShape(self.pen, points))


EOF = -1
SKIP = -2


class ParseError(Exception):

    def __init__(self, msg=None, filename=None, line=None, col=None):
        self.msg = msg
        self.filename = filename
        self.line = line
        self.col = col

    def __str__(self):
        return ':'.join([str(part) for part in (self.filename, self.line, self.col, self.msg) if part != None])


class Scanner:
    """Stateless scanner."""

    # should be overriden by derived classes
    tokens = []
    symbols = {}
    literals = {}
    ignorecase = False

    def __init__(self):
        flags = re.DOTALL
        if self.ignorecase:
            flags |= re.IGNORECASE
        self.tokens_re = re.compile(
            '|'.join(['(' + regexp + ')' for type, regexp, test_lit in self.tokens]),
             flags
        )

    def next(self, buf, pos):
        if pos >= len(buf):
            return EOF, '', pos
        mo = self.tokens_re.match(buf, pos)
        if mo:
            text = mo.group()
            type, regexp, test_lit = self.tokens[mo.lastindex - 1]
            pos = mo.end()
            if test_lit:
                type = self.literals.get(text, type)
            return type, text, pos
        else:
            c = buf[pos]
            return self.symbols.get(c, None), c, pos + 1


class Token:

    def __init__(self, type, text, line, col):
        self.type = type
        self.text = text
        self.line = line
        self.col = col


class Lexer:

    # should be overriden by derived classes
    scanner = None
    tabsize = 8

    newline_re = re.compile(r'\r\n?|\n')

    def __init__(self, buf = None, pos = 0, filename = None, fp = None):
        if fp is not None:
            try:
                fileno = fp.fileno()
                length = os.path.getsize(fp.name)
                import mmap
            except:
                # read whole file into memory
                buf = fp.read()
                pos = 0
            else:
                # map the whole file into memory
                if length:
                    # length must not be zero
                    buf = mmap.mmap(fileno, length, access = mmap.ACCESS_READ)
                    pos = os.lseek(fileno, 0, 1)
                else:
                    buf = ''
                    pos = 0

            if filename is None:
                try:
                    filename = fp.name
                except AttributeError:
                    filename = None

        self.buf = buf
        self.pos = pos
        self.line = 1
        self.col = 1
        self.filename = filename

    def next(self):
        while True:
            # save state
            pos = self.pos
            line = self.line
            col = self.col

            type, text, endpos = self.scanner.next(self.buf, pos)
            assert pos + len(text) == endpos
            self.consume(text)
            type, text = self.filter(type, text)
            self.pos = endpos

            if type == SKIP:
                continue
            elif type is None:
                msg = 'unexpected char '
                if text >= ' ' and text <= '~':
                    msg += "'%s'" % text
                else:
                    msg += "0x%X" % ord(text)
                raise ParseError(msg, self.filename, line, col)
            else:
                break
        return Token(type = type, text = text, line = line, col = col)

    def consume(self, text):
        # update line number
        pos = 0
        for mo in self.newline_re.finditer(text, pos):
            self.line += 1
            self.col = 1
            pos = mo.end()

        # update column number
        while True:
            tabpos = text.find('\t', pos)
            if tabpos == -1:
                break
            self.col += tabpos - pos
            self.col = ((self.col - 1)//self.tabsize + 1)*self.tabsize + 1
            pos = tabpos + 1
        self.col += len(text) - pos


class Parser:

    def __init__(self, lexer):
        self.lexer = lexer
        self.lookahead = self.lexer.next()

    def match(self, type):
        if self.lookahead.type != type:
            raise ParseError(
                msg = 'unexpected token %r' % self.lookahead.text, 
                filename = self.lexer.filename, 
                line = self.lookahead.line, 
                col = self.lookahead.col)

    def skip(self, type):
        while self.lookahead.type != type:
            self.consume()

    def consume(self):
        token = self.lookahead
        self.lookahead = self.lexer.next()
        return token


ID = 0
STR_ID = 1
HTML_ID = 2
EDGE_OP = 3

LSQUARE = 4
RSQUARE = 5
LCURLY = 6
RCURLY = 7
COMMA = 8
COLON = 9
SEMI = 10
EQUAL = 11
PLUS = 12

STRICT = 13
GRAPH = 14
DIGRAPH = 15
NODE = 16
EDGE = 17
SUBGRAPH = 18


class DotScanner(Scanner):

    # token regular expression table
    tokens = [
        # whitespace and comments
        (SKIP,
            r'[ \t\f\r\n\v]+|'
            r'//[^\r\n]*|'
            r'/\*.*?\*/|'
            r'#[^\r\n]*',
        False),

        # Alphanumeric IDs
        (ID, r'[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*', True),

        # Numeric IDs
        (ID, r'-?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)', False),

        # String IDs
        (STR_ID, r'"[^"\\]*(?:\\.[^"\\]*)*"', False),

        # HTML IDs
        (HTML_ID, r'<[^<>]*(?:<[^<>]*>[^<>]*)*>', False),

        # Edge operators
        (EDGE_OP, r'-[>-]', False),
    ]

    # symbol table
    symbols = {
        '[': LSQUARE,
        ']': RSQUARE,
        '{': LCURLY,
        '}': RCURLY,
        ',': COMMA,
        ':': COLON,
        ';': SEMI,
        '=': EQUAL,
        '+': PLUS,
    }

    # literal table
    literals = {
        'strict': STRICT,
        'graph': GRAPH,
        'digraph': DIGRAPH,
        'node': NODE,
        'edge': EDGE,
        'subgraph': SUBGRAPH,
    }

    ignorecase = True


class DotLexer(Lexer):

    scanner = DotScanner()

    def filter(self, type, text):
        # TODO: handle charset
        if type == STR_ID:
            text = text[1:-1]

            # line continuations
            text = text.replace('\\\r\n', '')
            text = text.replace('\\\r', '')
            text = text.replace('\\\n', '')

            # quotes
            text = text.replace('\\"', '"')

            # layout engines recognize other escape codes (many non-standard)
            # but we don't translate them here

            type = ID

        elif type == HTML_ID:
            text = text[1:-1]
            type = ID

        return type, text


class DotParser(Parser):

    def __init__(self, lexer):
        Parser.__init__(self, lexer)
        self.graph_attrs = {}
        self.node_attrs = {}
        self.edge_attrs = {}

    def parse(self):
        self.parse_graph()
        self.match(EOF)

    def parse_graph(self):
        if self.lookahead.type == STRICT:
            self.consume()
        self.skip(LCURLY)
        self.consume()
        while self.lookahead.type != RCURLY:
            self.parse_stmt()
        self.consume()

    def parse_subgraph(self):
        id = None
        if self.lookahead.type == SUBGRAPH:
            self.consume()
            if self.lookahead.type == ID:
                id = self.lookahead.text
                self.consume()
        if self.lookahead.type == LCURLY:
            self.consume()
            while self.lookahead.type != RCURLY:
                self.parse_stmt()
            self.consume()
        return id

    def parse_stmt(self):
        if self.lookahead.type == GRAPH:
            self.consume()
            attrs = self.parse_attrs()
            self.graph_attrs.update(attrs)
            self.handle_graph(attrs)
        elif self.lookahead.type == NODE:
            self.consume()
            self.node_attrs.update(self.parse_attrs())
        elif self.lookahead.type == EDGE:
            self.consume()
            self.edge_attrs.update(self.parse_attrs())
        elif self.lookahead.type in (SUBGRAPH, LCURLY):
            self.parse_subgraph()
        else:
            id = self.parse_node_id()
            if self.lookahead.type == EDGE_OP:
                self.consume()
                node_ids = [id, self.parse_node_id()]
                while self.lookahead.type == EDGE_OP:
                    node_ids.append(self.parse_node_id())
                attrs = self.parse_attrs()
                for i in range(0, len(node_ids) - 1):
                    self.handle_edge(node_ids[i], node_ids[i + 1], attrs)
            elif self.lookahead.type == EQUAL:
                self.consume()
                self.parse_id()
            else:
                attrs = self.parse_attrs()
                self.handle_node(id, attrs)
        if self.lookahead.type == SEMI:
            self.consume()

    def parse_attrs(self):
        attrs = {}
        while self.lookahead.type == LSQUARE:
            self.consume()
            while self.lookahead.type != RSQUARE:
                name, value = self.parse_attr()
                attrs[name] = value
                if self.lookahead.type == COMMA:
                    self.consume()
            self.consume()
        return attrs

    def parse_attr(self):
        name = self.parse_id()
        if self.lookahead.type == EQUAL:
            self.consume()
            value = self.parse_id()
        else:
            value = 'true'
        return name, value

    def parse_node_id(self):
        node_id = self.parse_id()
        if self.lookahead.type == COLON:
            self.consume()
            port = self.parse_id()
            if self.lookahead.type == COLON:
                self.consume()
                compass_pt = self.parse_id()
            else:
                compass_pt = None
        else:
            port = None
            compass_pt = None
        # XXX: we don't really care about port and compass point values when parsing xdot
        return node_id

    def parse_id(self):
        self.match(ID)
        id = self.lookahead.text
        self.consume()
        return id

    def handle_graph(self, attrs):
        pass

    def handle_node(self, id, attrs):
        pass

    def handle_edge(self, src_id, dst_id, attrs):
        pass


class XDotParser(DotParser):

    XDOTVERSION = '1.6'

    def __init__(self, xdotcode):
        lexer = DotLexer(buf = xdotcode)
        DotParser.__init__(self, lexer)

        self.nodes = []
        self.edges = []
        self.shapes = []
        self.node_by_name = {}
        self.top_graph = True

    def handle_graph(self, attrs):
        if self.top_graph:
            # Check xdot version
            try:
                xdotversion = attrs['xdotversion']
            except KeyError:
                pass
            else:
                if float(xdotversion) > float(self.XDOTVERSION):
                    sys.stderr.write('warning: xdot version %s, but supported is %s\n' % (xdotversion, self.XDOTVERSION))

            # Parse bounding box
            try:
                bb = attrs['bb']
            except KeyError:
                return

            if bb:
                xmin, ymin, xmax, ymax = map(float, bb.split(","))

                self.xoffset = -xmin
                self.yoffset = -ymax
                self.xscale = 1.0
                self.yscale = -1.0
                # FIXME: scale from points to pixels

                self.width  = max(xmax - xmin, 1)
                self.height = max(ymax - ymin, 1)

                self.top_graph = False

        for attr in ("_draw_", "_ldraw_", "_hdraw_", "_tdraw_", "_hldraw_", "_tldraw_"):
            if attr in attrs:
                parser = XDotAttrParser(self, attrs[attr])
                self.shapes.extend(parser.parse())

    def handle_node(self, id, attrs):
        try:
            pos = attrs['pos']
        except KeyError:
            return

        x, y = self.parse_node_pos(pos)
        w = float(attrs.get('width', 0))*72
        h = float(attrs.get('height', 0))*72
        shapes = []
        for attr in ("_draw_", "_ldraw_"):
            if attr in attrs:
                parser = XDotAttrParser(self, attrs[attr])
                shapes.extend(parser.parse())
        url = attrs.get('URL', None)
        node = Node(id, x, y, w, h, shapes, url)
        self.node_by_name[id] = node
        if shapes:
            self.nodes.append(node)

    def handle_edge(self, src_id, dst_id, attrs):
        try:
            pos = attrs['pos']
        except KeyError:
            return

        points = self.parse_edge_pos(pos)
        shapes = []
        for attr in ("_draw_", "_ldraw_", "_hdraw_", "_tdraw_", "_hldraw_", "_tldraw_"):
            if attr in attrs:
                parser = XDotAttrParser(self, attrs[attr])
                shapes.extend(parser.parse())
        if shapes:
            src = self.node_by_name[src_id]
            dst = self.node_by_name[dst_id]
            self.edges.append(Edge(src, dst, points, shapes))

    def parse(self):
        DotParser.parse(self)

        return Graph(self.width, self.height, self.shapes, self.nodes, self.edges)

    def parse_node_pos(self, pos):
        x, y = pos.split(",")
        return self.transform(float(x), float(y))

    def parse_edge_pos(self, pos):
        points = []
        for entry in pos.split(' '):
            fields = entry.split(',')
            try:
                x, y = fields
            except ValueError:
                # TODO: handle start/end points
                continue
            else:
                points.append(self.transform(float(x), float(y)))
        return points

    def transform(self, x, y):
        # XXX: this is not the right place for this code
        x = (x + self.xoffset)*self.xscale
        y = (y + self.yoffset)*self.yscale
        return x, y


class Animation(object):

    step = 0.03 # seconds

    def __init__(self, dot_widget):
        self.dot_widget = dot_widget
        self.timeout_id = None

    def start(self):
        self.timeout_id = gobject.timeout_add(int(self.step * 1000), self.tick)

    def stop(self):
        self.dot_widget.animation = NoAnimation(self.dot_widget)
        if self.timeout_id is not None:
            gobject.source_remove(self.timeout_id)
            self.timeout_id = None

    def tick(self):
        self.stop()


class NoAnimation(Animation):

    def start(self):
        pass

    def stop(self):
        pass


class LinearAnimation(Animation):

    duration = 0.6

    def start(self):
        self.started = time.time()
        Animation.start(self)

    def tick(self):
        t = (time.time() - self.started) / self.duration
        self.animate(max(0, min(t, 1)))
        return (t < 1)

    def animate(self, t):
        pass


class MoveToAnimation(LinearAnimation):

    def __init__(self, dot_widget, target_x, target_y):
        Animation.__init__(self, dot_widget)
        self.source_x = dot_widget.x
        self.source_y = dot_widget.y
        self.target_x = target_x
        self.target_y = target_y

    def animate(self, t):
        sx, sy = self.source_x, self.source_y
        tx, ty = self.target_x, self.target_y
        self.dot_widget.x = tx * t + sx * (1-t)
        self.dot_widget.y = ty * t + sy * (1-t)
        self.dot_widget.queue_draw()


class ZoomToAnimation(MoveToAnimation):

    def __init__(self, dot_widget, target_x, target_y):
        MoveToAnimation.__init__(self, dot_widget, target_x, target_y)
        self.source_zoom = dot_widget.zoom_ratio
        self.target_zoom = self.source_zoom
        self.extra_zoom = 0

        middle_zoom = 0.5 * (self.source_zoom + self.target_zoom)

        distance = math.hypot(self.source_x - self.target_x,
                              self.source_y - self.target_y)
        rect = self.dot_widget.get_allocation()
        visible = min(rect.width, rect.height) / self.dot_widget.zoom_ratio
        visible *= 0.9
        if distance > 0:
            desired_middle_zoom = visible / distance
            self.extra_zoom = min(0, 4 * (desired_middle_zoom - middle_zoom))

    def animate(self, t):
        a, b, c = self.source_zoom, self.extra_zoom, self.target_zoom
        self.dot_widget.zoom_ratio = c*t + b*t*(1-t) + a*(1-t)
        self.dot_widget.zoom_to_fit_on_resize = False
        MoveToAnimation.animate(self, t)


class DragAction(object):

    def __init__(self, dot_widget):
        self.dot_widget = dot_widget

    def on_button_press(self, event):
        self.startmousex = self.prevmousex = event.x
        self.startmousey = self.prevmousey = event.y
        self.start()

    def on_motion_notify(self, event):
        if event.is_hint:
            x, y, state = event.window.get_pointer()
        else:
            x, y, state = event.x, event.y, event.state
        deltax = self.prevmousex - x
        deltay = self.prevmousey - y
        self.drag(deltax, deltay)
        self.prevmousex = x
        self.prevmousey = y

    def on_button_release(self, event):
        self.stopmousex = event.x
        self.stopmousey = event.y
        self.stop()

    def draw(self, cr):
        pass

    def start(self):
        pass

    def drag(self, deltax, deltay):
        pass

    def stop(self):
        pass

    def abort(self):
        pass


class NullAction(DragAction):

    def on_motion_notify(self, event):
        if event.is_hint:
            x, y, state = event.window.get_pointer()
        else:
            x, y, state = event.x, event.y, event.state
        dot_widget = self.dot_widget
        item = dot_widget.get_url(x, y)
        if item is None:
            item = dot_widget.get_jump(x, y)
        if item is not None:
            dot_widget.window.set_cursor(gtk.gdk.Cursor(gtk.gdk.HAND2))
            dot_widget.set_highlight(item.highlight)
        else:
            dot_widget.window.set_cursor(gtk.gdk.Cursor(gtk.gdk.ARROW))
            dot_widget.set_highlight(None)


class PanAction(DragAction):

    def start(self):
        self.dot_widget.window.set_cursor(gtk.gdk.Cursor(gtk.gdk.FLEUR))

    def drag(self, deltax, deltay):
        self.dot_widget.x += deltax / self.dot_widget.zoom_ratio
        self.dot_widget.y += deltay / self.dot_widget.zoom_ratio
        self.dot_widget.queue_draw()

    def stop(self):
        self.dot_widget.window.set_cursor(gtk.gdk.Cursor(gtk.gdk.ARROW))

    abort = stop


class ZoomAction(DragAction):

    def drag(self, deltax, deltay):
        self.dot_widget.zoom_ratio *= 1.005 ** (deltax + deltay)
        self.dot_widget.zoom_to_fit_on_resize = False
        self.dot_widget.queue_draw()

    def stop(self):
        self.dot_widget.queue_draw()


class ZoomAreaAction(DragAction):

    def drag(self, deltax, deltay):
        self.dot_widget.queue_draw()

    def draw(self, cr):
        cr.save()
        cr.set_source_rgba(.5, .5, 1.0, 0.25)
        cr.rectangle(self.startmousex, self.startmousey,
                     self.prevmousex - self.startmousex,
                     self.prevmousey - self.startmousey)
        cr.fill()
        cr.set_source_rgba(.5, .5, 1.0, 1.0)
        cr.set_line_width(1)
        cr.rectangle(self.startmousex - .5, self.startmousey - .5,
                     self.prevmousex - self.startmousex + 1,
                     self.prevmousey - self.startmousey + 1)
        cr.stroke()
        cr.restore()

    def stop(self):
        x1, y1 = self.dot_widget.window2graph(self.startmousex,
                                              self.startmousey)
        x2, y2 = self.dot_widget.window2graph(self.stopmousex,
                                              self.stopmousey)
        self.dot_widget.zoom_to_area(x1, y1, x2, y2)

    def abort(self):
        self.dot_widget.queue_draw()


class DotWidget(gtk.DrawingArea):
    """PyGTK widget that draws dot graphs."""

    __gsignals__ = {
        'expose-event': 'override',
        'clicked' : (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_STRING, gtk.gdk.Event))
    }

    filter = 'dot'

    def __init__(self):
        gtk.DrawingArea.__init__(self)

        self.graph = Graph()
        self.openfilename = None

        self.set_flags(gtk.CAN_FOCUS)

        self.add_events(gtk.gdk.BUTTON_PRESS_MASK | gtk.gdk.BUTTON_RELEASE_MASK)
        self.connect("button-press-event", self.on_area_button_press)
        self.connect("button-release-event", self.on_area_button_release)
        self.add_events(gtk.gdk.POINTER_MOTION_MASK | gtk.gdk.POINTER_MOTION_HINT_MASK | gtk.gdk.BUTTON_RELEASE_MASK)
        self.connect("motion-notify-event", self.on_area_motion_notify)
        self.connect("scroll-event", self.on_area_scroll_event)
        self.connect("size-allocate", self.on_area_size_allocate)

        self.connect('key-press-event', self.on_key_press_event)
        self.last_mtime = None

        gobject.timeout_add(1000, self.update)

        self.x, self.y = 0.0, 0.0
        self.zoom_ratio = 1.0
        self.zoom_to_fit_on_resize = False
        self.animation = NoAnimation(self)
        self.drag_action = NullAction(self)
        self.presstime = None
        self.highlight = None

    def set_filter(self, filter):
        self.filter = filter

    def run_filter(self, dotcode):
        if not self.filter:
            return dotcode
        p = subprocess.Popen(
            [self.filter, '-Txdot'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            universal_newlines=True
        )
        xdotcode, error = p.communicate(dotcode)
        sys.stderr.write(error)
        if p.returncode != 0:
            dialog = gtk.MessageDialog(type=gtk.MESSAGE_ERROR,
                                       message_format=error,
                                       buttons=gtk.BUTTONS_OK)
            dialog.set_title('Dot Viewer')
            dialog.run()
            dialog.destroy()
            return None
        return xdotcode

    def set_dotcode(self, dotcode, filename=None):
        self.openfilename = None
        if isinstance(dotcode, unicode):
            dotcode = dotcode.encode('utf8')
        xdotcode = self.run_filter(dotcode)
        if xdotcode is None:
            return False
        try:
            self.set_xdotcode(xdotcode)
        except ParseError as ex:
            dialog = gtk.MessageDialog(type=gtk.MESSAGE_ERROR,
                                       message_format=str(ex),
                                       buttons=gtk.BUTTONS_OK)
            dialog.set_title('Dot Viewer')
            dialog.run()
            dialog.destroy()
            return False
        else:
            if filename is None:
                self.last_mtime = None
            else:
                self.last_mtime = os.stat(filename).st_mtime
            self.openfilename = filename
            return True

    def set_xdotcode(self, xdotcode):
        parser = XDotParser(xdotcode)
        self.graph = parser.parse()
        self.zoom_image(self.zoom_ratio, center=True)

    def reload(self):
        if self.openfilename is not None:
            try:
                fp = file(self.openfilename, 'rt')
                self.set_dotcode(fp.read(), self.openfilename)
                fp.close()
            except IOError:
                pass

    def update(self):
        if self.openfilename is not None:
            current_mtime = os.stat(self.openfilename).st_mtime
            if current_mtime != self.last_mtime:
                self.last_mtime = current_mtime
                self.reload()
        return True

    def do_expose_event(self, event):
        cr = self.window.cairo_create()

        # set a clip region for the expose event
        cr.rectangle(
            event.area.x, event.area.y,
            event.area.width, event.area.height
        )
        cr.clip()

        cr.set_source_rgba(1.0, 1.0, 1.0, 1.0)
        cr.paint()

        cr.save()
        rect = self.get_allocation()
        cr.translate(0.5*rect.width, 0.5*rect.height)
        cr.scale(self.zoom_ratio, self.zoom_ratio)
        cr.translate(-self.x, -self.y)

        self.graph.draw(cr, highlight_items=self.highlight)
        cr.restore()

        self.drag_action.draw(cr)

        return False

    def get_current_pos(self):
        return self.x, self.y

    def set_current_pos(self, x, y):
        self.x = x
        self.y = y
        self.queue_draw()

    def set_highlight(self, items):
        if self.highlight != items:
            self.highlight = items
            self.queue_draw()

    def zoom_image(self, zoom_ratio, center=False, pos=None):
        # Constrain zoom ratio to a sane range to prevent numeric instability.
        zoom_ratio = min(zoom_ratio, 1E4)
        zoom_ratio = max(zoom_ratio, 1E-6)

        if center:
            self.x = self.graph.width/2
            self.y = self.graph.height/2
        elif pos is not None:
            rect = self.get_allocation()
            x, y = pos
            x -= 0.5*rect.width
            y -= 0.5*rect.height
            self.x += x / self.zoom_ratio - x / zoom_ratio
            self.y += y / self.zoom_ratio - y / zoom_ratio
        self.zoom_ratio = zoom_ratio
        self.zoom_to_fit_on_resize = False
        self.queue_draw()

    def zoom_to_area(self, x1, y1, x2, y2):
        rect = self.get_allocation()
        width = abs(x1 - x2)
        height = abs(y1 - y2)
        if width == 0 and height == 0:
            self.zoom_ratio *= self.ZOOM_INCREMENT
        else:
            self.zoom_ratio = min(
                float(rect.width)/float(width),
                float(rect.height)/float(height)
            )
        self.zoom_to_fit_on_resize = False
        self.x = (x1 + x2) / 2
        self.y = (y1 + y2) / 2
        self.queue_draw()

    def zoom_to_fit(self):
        rect = self.get_allocation()
        rect.x += self.ZOOM_TO_FIT_MARGIN
        rect.y += self.ZOOM_TO_FIT_MARGIN
        rect.width -= 2 * self.ZOOM_TO_FIT_MARGIN
        rect.height -= 2 * self.ZOOM_TO_FIT_MARGIN
        zoom_ratio = min(
            float(rect.width)/float(self.graph.width),
            float(rect.height)/float(self.graph.height)
        )
        self.zoom_image(zoom_ratio, center=True)
        self.zoom_to_fit_on_resize = True

    ZOOM_INCREMENT = 1.25
    ZOOM_TO_FIT_MARGIN = 12

    def on_zoom_in(self, action):
        self.zoom_image(self.zoom_ratio * self.ZOOM_INCREMENT)

    def on_zoom_out(self, action):
        self.zoom_image(self.zoom_ratio / self.ZOOM_INCREMENT)

    def on_zoom_fit(self, action):
        self.zoom_to_fit()

    def on_zoom_100(self, action):
        self.zoom_image(1.0)

    POS_INCREMENT = 100

    def on_key_press_event(self, widget, event):
        if event.keyval == gtk.keysyms.Left:
            self.x -= self.POS_INCREMENT/self.zoom_ratio
            self.queue_draw()
            return True
        if event.keyval == gtk.keysyms.Right:
            self.x += self.POS_INCREMENT/self.zoom_ratio
            self.queue_draw()
            return True
        if event.keyval == gtk.keysyms.Up:
            self.y -= self.POS_INCREMENT/self.zoom_ratio
            self.queue_draw()
            return True
        if event.keyval == gtk.keysyms.Down:
            self.y += self.POS_INCREMENT/self.zoom_ratio
            self.queue_draw()
            return True
        if event.keyval in (gtk.keysyms.Page_Up,
                            gtk.keysyms.plus,
                            gtk.keysyms.equal,
                            gtk.keysyms.KP_Add):
            self.zoom_image(self.zoom_ratio * self.ZOOM_INCREMENT)
            self.queue_draw()
            return True
        if event.keyval in (gtk.keysyms.Page_Down,
                            gtk.keysyms.minus,
                            gtk.keysyms.KP_Subtract):
            self.zoom_image(self.zoom_ratio / self.ZOOM_INCREMENT)
            self.queue_draw()
            return True
        if event.keyval == gtk.keysyms.Escape:
            self.drag_action.abort()
            self.drag_action = NullAction(self)
            return True
        if event.keyval == gtk.keysyms.r:
            self.reload()
            return True
        if event.keyval == gtk.keysyms.f:
            win = widget.get_toplevel()
            find_toolitem = win.uimanager.get_widget('/ToolBar/Find')
            textentry = find_toolitem.get_children()
            win.set_focus(textentry[0])
            return True
        if event.keyval == gtk.keysyms.q:
            gtk.main_quit()
            return True
        if event.keyval == gtk.keysyms.p:
            self.on_print()
            return True
        return False

    print_settings = None
    def on_print(self, action=None):
        print_op = gtk.PrintOperation()

        if self.print_settings != None:
            print_op.set_print_settings(self.print_settings)

        print_op.connect("begin_print", self.begin_print)
        print_op.connect("draw_page", self.draw_page)

        res = print_op.run(gtk.PRINT_OPERATION_ACTION_PRINT_DIALOG, self.parent.parent)

        if res == gtk.PRINT_OPERATION_RESULT_APPLY:
            print_settings = print_op.get_print_settings()

    def begin_print(self, operation, context):
        operation.set_n_pages(1)
        return True

    def draw_page(self, operation, context, page_nr):
        cr = context.get_cairo_context()

        rect = self.get_allocation()
        cr.translate(0.5*rect.width, 0.5*rect.height)
        cr.scale(self.zoom_ratio, self.zoom_ratio)
        cr.translate(-self.x, -self.y)

        self.graph.draw(cr, highlight_items=self.highlight)

    def get_drag_action(self, event):
        state = event.state
        if event.button in (1, 2): # left or middle button
            if state & gtk.gdk.CONTROL_MASK:
                return ZoomAction
            elif state & gtk.gdk.SHIFT_MASK:
                return ZoomAreaAction
            else:
                return PanAction
        return NullAction

    def on_area_button_press(self, area, event):
        self.animation.stop()
        self.drag_action.abort()
        action_type = self.get_drag_action(event)
        self.drag_action = action_type(self)
        self.drag_action.on_button_press(event)
        self.presstime = time.time()
        self.pressx = event.x
        self.pressy = event.y
        return False

    def is_click(self, event, click_fuzz=4, click_timeout=1.0):
        assert event.type == gtk.gdk.BUTTON_RELEASE
        if self.presstime is None:
            # got a button release without seeing the press?
            return False
        # XXX instead of doing this complicated logic, shouldn't we listen
        # for gtk's clicked event instead?
        deltax = self.pressx - event.x
        deltay = self.pressy - event.y
        return (time.time() < self.presstime + click_timeout
                and math.hypot(deltax, deltay) < click_fuzz)

    def on_click(self, element, event):
        """Override this method in subclass to process
        click events. Note that element can be None
        (click on empty space)."""
        return False

    def on_area_button_release(self, area, event):
        self.drag_action.on_button_release(event)
        self.drag_action = NullAction(self)
        x, y = int(event.x), int(event.y)
        if self.is_click(event):
            el = self.get_element(x, y)
            if self.on_click(el, event):
                return True

            if event.button == 1:
                url = self.get_url(x, y)
                if url is not None:
                    self.emit('clicked', unicode(url.url), event)
                else:
                    jump = self.get_jump(x, y)
                    if jump is not None:
                        self.animate_to(jump.x, jump.y)

                return True

        if event.button == 1 or event.button == 2:
            return True
        return False

    def on_area_scroll_event(self, area, event):
        if event.direction == gtk.gdk.SCROLL_UP:
            self.zoom_image(self.zoom_ratio * self.ZOOM_INCREMENT,
                            pos=(event.x, event.y))
            return True
        if event.direction == gtk.gdk.SCROLL_DOWN:
            self.zoom_image(self.zoom_ratio / self.ZOOM_INCREMENT,
                            pos=(event.x, event.y))
            return True
        return False

    def on_area_motion_notify(self, area, event):
        self.drag_action.on_motion_notify(event)
        return True

    def on_area_size_allocate(self, area, allocation):
        if self.zoom_to_fit_on_resize:
            self.zoom_to_fit()

    def animate_to(self, x, y):
        self.animation = ZoomToAnimation(self, x, y)
        self.animation.start()

    def window2graph(self, x, y):
        rect = self.get_allocation()
        x -= 0.5*rect.width
        y -= 0.5*rect.height
        x /= self.zoom_ratio
        y /= self.zoom_ratio
        x += self.x
        y += self.y
        return x, y

    def get_element(self, x, y):
        x, y = self.window2graph(x, y)
        return self.graph.get_element(x, y)

    def get_url(self, x, y):
        x, y = self.window2graph(x, y)
        return self.graph.get_url(x, y)

    def get_jump(self, x, y):
        x, y = self.window2graph(x, y)
        return self.graph.get_jump(x, y)


class FindMenuToolAction(gtk.Action):
    __gtype_name__ = "FindMenuToolAction"

    def __init__(self, *args, **kw):
        gtk.Action.__init__(self, *args, **kw)
        self.set_tool_item_type(gtk.ToolItem)


class DotWindow(gtk.Window):

    ui = '''
    <ui>
        <toolbar name="ToolBar">
            <toolitem action="Open"/>
            <toolitem action="Reload"/>
            <toolitem action="Print"/>
            <separator/>
            <toolitem action="ZoomIn"/>
            <toolitem action="ZoomOut"/>
            <toolitem action="ZoomFit"/>
            <toolitem action="Zoom100"/>
            <separator/>
            <toolitem name="Find" action="Find"/>
        </toolbar>
    </ui>
    '''

    base_title = 'Dot Viewer'

    def __init__(self, widget=None):
        gtk.Window.__init__(self)

        self.graph = Graph()

        window = self

        window.set_title(self.base_title)
        window.set_default_size(512, 512)
        vbox = gtk.VBox()
        window.add(vbox)

        self.widget = widget or DotWidget()

        # Create a UIManager instance
        uimanager = self.uimanager = gtk.UIManager()

        # Add the accelerator group to the toplevel window
        accelgroup = uimanager.get_accel_group()
        window.add_accel_group(accelgroup)

        # Create an ActionGroup
        actiongroup = gtk.ActionGroup('Actions')
        self.actiongroup = actiongroup

        # Create actions
        actiongroup.add_actions((
            ('Open', gtk.STOCK_OPEN, None, None, None, self.on_open),
            ('Reload', gtk.STOCK_REFRESH, None, None, None, self.on_reload),
            ('Print', gtk.STOCK_PRINT, None, None, "Prints the currently visible part of the graph", self.widget.on_print),
            ('ZoomIn', gtk.STOCK_ZOOM_IN, None, None, None, self.widget.on_zoom_in),
            ('ZoomOut', gtk.STOCK_ZOOM_OUT, None, None, None, self.widget.on_zoom_out),
            ('ZoomFit', gtk.STOCK_ZOOM_FIT, None, None, None, self.widget.on_zoom_fit),
            ('Zoom100', gtk.STOCK_ZOOM_100, None, None, None, self.widget.on_zoom_100),
        ))

        find_action = FindMenuToolAction("Find", None,
                                          "Find a node by name", None)
        actiongroup.add_action(find_action)

        # Add the actiongroup to the uimanager
        uimanager.insert_action_group(actiongroup, 0)

        # Add a UI descrption
        uimanager.add_ui_from_string(self.ui)

        # Create a Toolbar
        toolbar = uimanager.get_widget('/ToolBar')
        vbox.pack_start(toolbar, False)

        vbox.pack_start(self.widget)

        self.last_open_dir = "."

        self.set_focus(self.widget)

        # Add Find text search
        find_toolitem = uimanager.get_widget('/ToolBar/Find')
        self.textentry = gtk.Entry(max=20)
        self.textentry.set_icon_from_stock(0, gtk.STOCK_FIND)
        find_toolitem.add(self.textentry)

        self.textentry.set_activates_default(True)
        self.textentry.connect ("activate", self.textentry_activate, self.textentry);
        self.textentry.connect ("changed", self.textentry_changed, self.textentry);

        self.show_all()

    def find_text(self, entry_text):
        found_items = []
        dot_widget = self.widget
        regexp = re.compile(entry_text)
        for node in dot_widget.graph.nodes:
            if node.search_text(regexp):
                found_items.append(node)
        return found_items

    def textentry_changed(self, widget, entry):
        entry_text = entry.get_text()
        dot_widget = self.widget        
        if not entry_text:
            dot_widget.set_highlight(None)
            return

        found_items = self.find_text(entry_text)
        dot_widget.set_highlight(found_items)

    def textentry_activate(self, widget, entry):
        entry_text = entry.get_text()
        dot_widget = self.widget        
        if not entry_text:
            dot_widget.set_highlight(None)
            return;

        found_items = self.find_text(entry_text)
        dot_widget.set_highlight(found_items)
        if(len(found_items) == 1):
            dot_widget.animate_to(found_items[0].x, found_items[0].y)

    def set_filter(self, filter):
        self.widget.set_filter(filter)

    def set_dotcode(self, dotcode, filename=None):
        if self.widget.set_dotcode(dotcode, filename):
            self.update_title(filename)
            self.widget.zoom_to_fit()

    def set_xdotcode(self, xdotcode, filename=None):
        if self.widget.set_xdotcode(xdotcode):
            self.update_title(filename)
            self.widget.zoom_to_fit()

    def update_title(self, filename=None):
        if filename is None:
            self.set_title(self.base_title)
        else:
            self.set_title(os.path.basename(filename) + ' - ' + self.base_title)

    def open_file(self, filename):
        try:
            fp = file(filename, 'rt')
            self.set_dotcode(fp.read(), filename)
            fp.close()
        except IOError as ex:
            dlg = gtk.MessageDialog(type=gtk.MESSAGE_ERROR,
                                    message_format=str(ex),
                                    buttons=gtk.BUTTONS_OK)
            dlg.set_title(self.base_title)
            dlg.run()
            dlg.destroy()

    def on_open(self, action):
        chooser = gtk.FileChooserDialog(title="Open dot File",
                                        action=gtk.FILE_CHOOSER_ACTION_OPEN,
                                        buttons=(gtk.STOCK_CANCEL,
                                                 gtk.RESPONSE_CANCEL,
                                                 gtk.STOCK_OPEN,
                                                 gtk.RESPONSE_OK))
        chooser.set_default_response(gtk.RESPONSE_OK)
        chooser.set_current_folder(self.last_open_dir)
        filter = gtk.FileFilter()
        filter.set_name("Graphviz dot files")
        filter.add_pattern("*.dot")
        chooser.add_filter(filter)
        filter = gtk.FileFilter()
        filter.set_name("All files")
        filter.add_pattern("*")
        chooser.add_filter(filter)
        if chooser.run() == gtk.RESPONSE_OK:
            filename = chooser.get_filename()
            self.last_open_dir = chooser.get_current_folder()
            chooser.destroy()
            self.open_file(filename)
        else:
            chooser.destroy()

    def on_reload(self, action):
        self.widget.reload()


class OptionParser(optparse.OptionParser):

    def format_epilog(self, formatter):
        # Prevent stripping the newlines in epilog message
        # http://stackoverflow.com/questions/1857346/python-optparse-how-to-include-additional-info-in-usage-output
        return self.epilog


def main():

    parser = OptionParser(
        usage='\n\t%prog [file]',
        epilog='''
Shortcuts:
  Up, Down, Left, Right     scroll
  PageUp, +, =              zoom in
  PageDown, -               zoom out
  R                         reload dot file
  F                         find
  Q                         quit
  P                         print
  Escape                    halt animation
  Ctrl-drag                 zoom in/out
  Shift-drag                zooms an area
'''
    )
    parser.add_option(
        '-f', '--filter',
        type='choice', choices=('dot', 'neato', 'twopi', 'circo', 'fdp'),
        dest='filter', default='dot',
        help='graphviz filter: dot, neato, twopi, circo, or fdp [default: %default]')
    parser.add_option(
        '-n', '--no-filter',
        action='store_const', const=None, dest='filter',
        help='assume input is already filtered into xdot format (use e.g. dot -Txdot)')

    (options, args) = parser.parse_args(sys.argv[1:])
    if len(args) > 1:
        parser.error('incorrect number of arguments')

    win = DotWindow()
    win.connect('destroy', gtk.main_quit)
    win.set_filter(options.filter)
    if len(args) == 0:
        if not sys.stdin.isatty():
            win.set_dotcode(sys.stdin.read())
    else:
        if args[0] == '-':
            win.set_dotcode(sys.stdin.read())
        else:
            win.open_file(args[0])
    gtk.main()


# Apache-Style Software License for ColorBrewer software and ColorBrewer Color
# Schemes, Version 1.1
# 
# Copyright (c) 2002 Cynthia Brewer, Mark Harrower, and The Pennsylvania State
# University. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#    1. Redistributions as source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.  
#
#    2. The end-user documentation included with the redistribution, if any,
#    must include the following acknowledgment:
# 
#       This product includes color specifications and designs developed by
#       Cynthia Brewer (http://colorbrewer.org/).
# 
#    Alternately, this acknowledgment may appear in the software itself, if and
#    wherever such third-party acknowledgments normally appear.  
#
#    3. The name "ColorBrewer" must not be used to endorse or promote products
#    derived from this software without prior written permission. For written
#    permission, please contact Cynthia Brewer at cbrewer@psu.edu.
#
#    4. Products derived from this software may not be called "ColorBrewer",
#    nor may "ColorBrewer" appear in their name, without prior written
#    permission of Cynthia Brewer. 
# 
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CYNTHIA
# BREWER, MARK HARROWER, OR THE PENNSYLVANIA STATE UNIVERSITY BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
brewer_colors = {
    'accent3': [(127, 201, 127), (190, 174, 212), (253, 192, 134)],
    'accent4': [(127, 201, 127), (190, 174, 212), (253, 192, 134), (255, 255, 153)],
    'accent5': [(127, 201, 127), (190, 174, 212), (253, 192, 134), (255, 255, 153), (56, 108, 176)],
    'accent6': [(127, 201, 127), (190, 174, 212), (253, 192, 134), (255, 255, 153), (56, 108, 176), (240, 2, 127)],
    'accent7': [(127, 201, 127), (190, 174, 212), (253, 192, 134), (255, 255, 153), (56, 108, 176), (240, 2, 127), (191, 91, 23)],
    'accent8': [(127, 201, 127), (190, 174, 212), (253, 192, 134), (255, 255, 153), (56, 108, 176), (240, 2, 127), (191, 91, 23), (102, 102, 102)],
    'blues3': [(222, 235, 247), (158, 202, 225), (49, 130, 189)],
    'blues4': [(239, 243, 255), (189, 215, 231), (107, 174, 214), (33, 113, 181)],
    'blues5': [(239, 243, 255), (189, 215, 231), (107, 174, 214), (49, 130, 189), (8, 81, 156)],
    'blues6': [(239, 243, 255), (198, 219, 239), (158, 202, 225), (107, 174, 214), (49, 130, 189), (8, 81, 156)],
    'blues7': [(239, 243, 255), (198, 219, 239), (158, 202, 225), (107, 174, 214), (66, 146, 198), (33, 113, 181), (8, 69, 148)],
    'blues8': [(247, 251, 255), (222, 235, 247), (198, 219, 239), (158, 202, 225), (107, 174, 214), (66, 146, 198), (33, 113, 181), (8, 69, 148)],
    'blues9': [(247, 251, 255), (222, 235, 247), (198, 219, 239), (158, 202, 225), (107, 174, 214), (66, 146, 198), (33, 113, 181), (8, 81, 156), (8, 48, 107)],
    'brbg10': [(84, 48, 5), (0, 60, 48), (140, 81, 10), (191, 129, 45), (223, 194, 125), (246, 232, 195), (199, 234, 229), (128, 205, 193), (53, 151, 143), (1, 102, 94)],
    'brbg11': [(84, 48, 5), (1, 102, 94), (0, 60, 48), (140, 81, 10), (191, 129, 45), (223, 194, 125), (246, 232, 195), (245, 245, 245), (199, 234, 229), (128, 205, 193), (53, 151, 143)],
    'brbg3': [(216, 179, 101), (245, 245, 245), (90, 180, 172)],
    'brbg4': [(166, 97, 26), (223, 194, 125), (128, 205, 193), (1, 133, 113)],
    'brbg5': [(166, 97, 26), (223, 194, 125), (245, 245, 245), (128, 205, 193), (1, 133, 113)],
    'brbg6': [(140, 81, 10), (216, 179, 101), (246, 232, 195), (199, 234, 229), (90, 180, 172), (1, 102, 94)],
    'brbg7': [(140, 81, 10), (216, 179, 101), (246, 232, 195), (245, 245, 245), (199, 234, 229), (90, 180, 172), (1, 102, 94)],
    'brbg8': [(140, 81, 10), (191, 129, 45), (223, 194, 125), (246, 232, 195), (199, 234, 229), (128, 205, 193), (53, 151, 143), (1, 102, 94)],
    'brbg9': [(140, 81, 10), (191, 129, 45), (223, 194, 125), (246, 232, 195), (245, 245, 245), (199, 234, 229), (128, 205, 193), (53, 151, 143), (1, 102, 94)],
    'bugn3': [(229, 245, 249), (153, 216, 201), (44, 162, 95)],
    'bugn4': [(237, 248, 251), (178, 226, 226), (102, 194, 164), (35, 139, 69)],
    'bugn5': [(237, 248, 251), (178, 226, 226), (102, 194, 164), (44, 162, 95), (0, 109, 44)],
    'bugn6': [(237, 248, 251), (204, 236, 230), (153, 216, 201), (102, 194, 164), (44, 162, 95), (0, 109, 44)],
    'bugn7': [(237, 248, 251), (204, 236, 230), (153, 216, 201), (102, 194, 164), (65, 174, 118), (35, 139, 69), (0, 88, 36)],
    'bugn8': [(247, 252, 253), (229, 245, 249), (204, 236, 230), (153, 216, 201), (102, 194, 164), (65, 174, 118), (35, 139, 69), (0, 88, 36)],
    'bugn9': [(247, 252, 253), (229, 245, 249), (204, 236, 230), (153, 216, 201), (102, 194, 164), (65, 174, 118), (35, 139, 69), (0, 109, 44), (0, 68, 27)],
    'bupu3': [(224, 236, 244), (158, 188, 218), (136, 86, 167)],
    'bupu4': [(237, 248, 251), (179, 205, 227), (140, 150, 198), (136, 65, 157)],
    'bupu5': [(237, 248, 251), (179, 205, 227), (140, 150, 198), (136, 86, 167), (129, 15, 124)],
    'bupu6': [(237, 248, 251), (191, 211, 230), (158, 188, 218), (140, 150, 198), (136, 86, 167), (129, 15, 124)],
    'bupu7': [(237, 248, 251), (191, 211, 230), (158, 188, 218), (140, 150, 198), (140, 107, 177), (136, 65, 157), (110, 1, 107)],
    'bupu8': [(247, 252, 253), (224, 236, 244), (191, 211, 230), (158, 188, 218), (140, 150, 198), (140, 107, 177), (136, 65, 157), (110, 1, 107)],
    'bupu9': [(247, 252, 253), (224, 236, 244), (191, 211, 230), (158, 188, 218), (140, 150, 198), (140, 107, 177), (136, 65, 157), (129, 15, 124), (77, 0, 75)],
    'dark23': [(27, 158, 119), (217, 95, 2), (117, 112, 179)],
    'dark24': [(27, 158, 119), (217, 95, 2), (117, 112, 179), (231, 41, 138)],
    'dark25': [(27, 158, 119), (217, 95, 2), (117, 112, 179), (231, 41, 138), (102, 166, 30)],
    'dark26': [(27, 158, 119), (217, 95, 2), (117, 112, 179), (231, 41, 138), (102, 166, 30), (230, 171, 2)],
    'dark27': [(27, 158, 119), (217, 95, 2), (117, 112, 179), (231, 41, 138), (102, 166, 30), (230, 171, 2), (166, 118, 29)],
    'dark28': [(27, 158, 119), (217, 95, 2), (117, 112, 179), (231, 41, 138), (102, 166, 30), (230, 171, 2), (166, 118, 29), (102, 102, 102)],
    'gnbu3': [(224, 243, 219), (168, 221, 181), (67, 162, 202)],
    'gnbu4': [(240, 249, 232), (186, 228, 188), (123, 204, 196), (43, 140, 190)],
    'gnbu5': [(240, 249, 232), (186, 228, 188), (123, 204, 196), (67, 162, 202), (8, 104, 172)],
    'gnbu6': [(240, 249, 232), (204, 235, 197), (168, 221, 181), (123, 204, 196), (67, 162, 202), (8, 104, 172)],
    'gnbu7': [(240, 249, 232), (204, 235, 197), (168, 221, 181), (123, 204, 196), (78, 179, 211), (43, 140, 190), (8, 88, 158)],
    'gnbu8': [(247, 252, 240), (224, 243, 219), (204, 235, 197), (168, 221, 181), (123, 204, 196), (78, 179, 211), (43, 140, 190), (8, 88, 158)],
    'gnbu9': [(247, 252, 240), (224, 243, 219), (204, 235, 197), (168, 221, 181), (123, 204, 196), (78, 179, 211), (43, 140, 190), (8, 104, 172), (8, 64, 129)],
    'greens3': [(229, 245, 224), (161, 217, 155), (49, 163, 84)],
    'greens4': [(237, 248, 233), (186, 228, 179), (116, 196, 118), (35, 139, 69)],
    'greens5': [(237, 248, 233), (186, 228, 179), (116, 196, 118), (49, 163, 84), (0, 109, 44)],
    'greens6': [(237, 248, 233), (199, 233, 192), (161, 217, 155), (116, 196, 118), (49, 163, 84), (0, 109, 44)],
    'greens7': [(237, 248, 233), (199, 233, 192), (161, 217, 155), (116, 196, 118), (65, 171, 93), (35, 139, 69), (0, 90, 50)],
    'greens8': [(247, 252, 245), (229, 245, 224), (199, 233, 192), (161, 217, 155), (116, 196, 118), (65, 171, 93), (35, 139, 69), (0, 90, 50)],
    'greens9': [(247, 252, 245), (229, 245, 224), (199, 233, 192), (161, 217, 155), (116, 196, 118), (65, 171, 93), (35, 139, 69), (0, 109, 44), (0, 68, 27)],
    'greys3': [(240, 240, 240), (189, 189, 189), (99, 99, 99)],
    'greys4': [(247, 247, 247), (204, 204, 204), (150, 150, 150), (82, 82, 82)],
    'greys5': [(247, 247, 247), (204, 204, 204), (150, 150, 150), (99, 99, 99), (37, 37, 37)],
    'greys6': [(247, 247, 247), (217, 217, 217), (189, 189, 189), (150, 150, 150), (99, 99, 99), (37, 37, 37)],
    'greys7': [(247, 247, 247), (217, 217, 217), (189, 189, 189), (150, 150, 150), (115, 115, 115), (82, 82, 82), (37, 37, 37)],
    'greys8': [(255, 255, 255), (240, 240, 240), (217, 217, 217), (189, 189, 189), (150, 150, 150), (115, 115, 115), (82, 82, 82), (37, 37, 37)],
    'greys9': [(255, 255, 255), (240, 240, 240), (217, 217, 217), (189, 189, 189), (150, 150, 150), (115, 115, 115), (82, 82, 82), (37, 37, 37), (0, 0, 0)],
    'oranges3': [(254, 230, 206), (253, 174, 107), (230, 85, 13)],
    'oranges4': [(254, 237, 222), (253, 190, 133), (253, 141, 60), (217, 71, 1)],
    'oranges5': [(254, 237, 222), (253, 190, 133), (253, 141, 60), (230, 85, 13), (166, 54, 3)],
    'oranges6': [(254, 237, 222), (253, 208, 162), (253, 174, 107), (253, 141, 60), (230, 85, 13), (166, 54, 3)],
    'oranges7': [(254, 237, 222), (253, 208, 162), (253, 174, 107), (253, 141, 60), (241, 105, 19), (217, 72, 1), (140, 45, 4)],
    'oranges8': [(255, 245, 235), (254, 230, 206), (253, 208, 162), (253, 174, 107), (253, 141, 60), (241, 105, 19), (217, 72, 1), (140, 45, 4)],
    'oranges9': [(255, 245, 235), (254, 230, 206), (253, 208, 162), (253, 174, 107), (253, 141, 60), (241, 105, 19), (217, 72, 1), (166, 54, 3), (127, 39, 4)],
    'orrd3': [(254, 232, 200), (253, 187, 132), (227, 74, 51)],
    'orrd4': [(254, 240, 217), (253, 204, 138), (252, 141, 89), (215, 48, 31)],
    'orrd5': [(254, 240, 217), (253, 204, 138), (252, 141, 89), (227, 74, 51), (179, 0, 0)],
    'orrd6': [(254, 240, 217), (253, 212, 158), (253, 187, 132), (252, 141, 89), (227, 74, 51), (179, 0, 0)],
    'orrd7': [(254, 240, 217), (253, 212, 158), (253, 187, 132), (252, 141, 89), (239, 101, 72), (215, 48, 31), (153, 0, 0)],
    'orrd8': [(255, 247, 236), (254, 232, 200), (253, 212, 158), (253, 187, 132), (252, 141, 89), (239, 101, 72), (215, 48, 31), (153, 0, 0)],
    'orrd9': [(255, 247, 236), (254, 232, 200), (253, 212, 158), (253, 187, 132), (252, 141, 89), (239, 101, 72), (215, 48, 31), (179, 0, 0), (127, 0, 0)],
    'paired10': [(166, 206, 227), (106, 61, 154), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111), (255, 127, 0), (202, 178, 214)],
    'paired11': [(166, 206, 227), (106, 61, 154), (255, 255, 153), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111), (255, 127, 0), (202, 178, 214)],
    'paired12': [(166, 206, 227), (106, 61, 154), (255, 255, 153), (177, 89, 40), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111), (255, 127, 0), (202, 178, 214)],
    'paired3': [(166, 206, 227), (31, 120, 180), (178, 223, 138)],
    'paired4': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44)],
    'paired5': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153)],
    'paired6': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28)],
    'paired7': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111)],
    'paired8': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111), (255, 127, 0)],
    'paired9': [(166, 206, 227), (31, 120, 180), (178, 223, 138), (51, 160, 44), (251, 154, 153), (227, 26, 28), (253, 191, 111), (255, 127, 0), (202, 178, 214)],
    'pastel13': [(251, 180, 174), (179, 205, 227), (204, 235, 197)],
    'pastel14': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228)],
    'pastel15': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228), (254, 217, 166)],
    'pastel16': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228), (254, 217, 166), (255, 255, 204)],
    'pastel17': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228), (254, 217, 166), (255, 255, 204), (229, 216, 189)],
    'pastel18': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228), (254, 217, 166), (255, 255, 204), (229, 216, 189), (253, 218, 236)],
    'pastel19': [(251, 180, 174), (179, 205, 227), (204, 235, 197), (222, 203, 228), (254, 217, 166), (255, 255, 204), (229, 216, 189), (253, 218, 236), (242, 242, 242)],
    'pastel23': [(179, 226, 205), (253, 205, 172), (203, 213, 232)],
    'pastel24': [(179, 226, 205), (253, 205, 172), (203, 213, 232), (244, 202, 228)],
    'pastel25': [(179, 226, 205), (253, 205, 172), (203, 213, 232), (244, 202, 228), (230, 245, 201)],
    'pastel26': [(179, 226, 205), (253, 205, 172), (203, 213, 232), (244, 202, 228), (230, 245, 201), (255, 242, 174)],
    'pastel27': [(179, 226, 205), (253, 205, 172), (203, 213, 232), (244, 202, 228), (230, 245, 201), (255, 242, 174), (241, 226, 204)],
    'pastel28': [(179, 226, 205), (253, 205, 172), (203, 213, 232), (244, 202, 228), (230, 245, 201), (255, 242, 174), (241, 226, 204), (204, 204, 204)],
    'piyg10': [(142, 1, 82), (39, 100, 25), (197, 27, 125), (222, 119, 174), (241, 182, 218), (253, 224, 239), (230, 245, 208), (184, 225, 134), (127, 188, 65), (77, 146, 33)],
    'piyg11': [(142, 1, 82), (77, 146, 33), (39, 100, 25), (197, 27, 125), (222, 119, 174), (241, 182, 218), (253, 224, 239), (247, 247, 247), (230, 245, 208), (184, 225, 134), (127, 188, 65)],
    'piyg3': [(233, 163, 201), (247, 247, 247), (161, 215, 106)],
    'piyg4': [(208, 28, 139), (241, 182, 218), (184, 225, 134), (77, 172, 38)],
    'piyg5': [(208, 28, 139), (241, 182, 218), (247, 247, 247), (184, 225, 134), (77, 172, 38)],
    'piyg6': [(197, 27, 125), (233, 163, 201), (253, 224, 239), (230, 245, 208), (161, 215, 106), (77, 146, 33)],
    'piyg7': [(197, 27, 125), (233, 163, 201), (253, 224, 239), (247, 247, 247), (230, 245, 208), (161, 215, 106), (77, 146, 33)],
    'piyg8': [(197, 27, 125), (222, 119, 174), (241, 182, 218), (253, 224, 239), (230, 245, 208), (184, 225, 134), (127, 188, 65), (77, 146, 33)],
    'piyg9': [(197, 27, 125), (222, 119, 174), (241, 182, 218), (253, 224, 239), (247, 247, 247), (230, 245, 208), (184, 225, 134), (127, 188, 65), (77, 146, 33)],
    'prgn10': [(64, 0, 75), (0, 68, 27), (118, 42, 131), (153, 112, 171), (194, 165, 207), (231, 212, 232), (217, 240, 211), (166, 219, 160), (90, 174, 97), (27, 120, 55)],
    'prgn11': [(64, 0, 75), (27, 120, 55), (0, 68, 27), (118, 42, 131), (153, 112, 171), (194, 165, 207), (231, 212, 232), (247, 247, 247), (217, 240, 211), (166, 219, 160), (90, 174, 97)],
    'prgn3': [(175, 141, 195), (247, 247, 247), (127, 191, 123)],
    'prgn4': [(123, 50, 148), (194, 165, 207), (166, 219, 160), (0, 136, 55)],
    'prgn5': [(123, 50, 148), (194, 165, 207), (247, 247, 247), (166, 219, 160), (0, 136, 55)],
    'prgn6': [(118, 42, 131), (175, 141, 195), (231, 212, 232), (217, 240, 211), (127, 191, 123), (27, 120, 55)],
    'prgn7': [(118, 42, 131), (175, 141, 195), (231, 212, 232), (247, 247, 247), (217, 240, 211), (127, 191, 123), (27, 120, 55)],
    'prgn8': [(118, 42, 131), (153, 112, 171), (194, 165, 207), (231, 212, 232), (217, 240, 211), (166, 219, 160), (90, 174, 97), (27, 120, 55)],
    'prgn9': [(118, 42, 131), (153, 112, 171), (194, 165, 207), (231, 212, 232), (247, 247, 247), (217, 240, 211), (166, 219, 160), (90, 174, 97), (27, 120, 55)],
    'pubu3': [(236, 231, 242), (166, 189, 219), (43, 140, 190)],
    'pubu4': [(241, 238, 246), (189, 201, 225), (116, 169, 207), (5, 112, 176)],
    'pubu5': [(241, 238, 246), (189, 201, 225), (116, 169, 207), (43, 140, 190), (4, 90, 141)],
    'pubu6': [(241, 238, 246), (208, 209, 230), (166, 189, 219), (116, 169, 207), (43, 140, 190), (4, 90, 141)],
    'pubu7': [(241, 238, 246), (208, 209, 230), (166, 189, 219), (116, 169, 207), (54, 144, 192), (5, 112, 176), (3, 78, 123)],
    'pubu8': [(255, 247, 251), (236, 231, 242), (208, 209, 230), (166, 189, 219), (116, 169, 207), (54, 144, 192), (5, 112, 176), (3, 78, 123)],
    'pubu9': [(255, 247, 251), (236, 231, 242), (208, 209, 230), (166, 189, 219), (116, 169, 207), (54, 144, 192), (5, 112, 176), (4, 90, 141), (2, 56, 88)],
    'pubugn3': [(236, 226, 240), (166, 189, 219), (28, 144, 153)],
    'pubugn4': [(246, 239, 247), (189, 201, 225), (103, 169, 207), (2, 129, 138)],
    'pubugn5': [(246, 239, 247), (189, 201, 225), (103, 169, 207), (28, 144, 153), (1, 108, 89)],
    'pubugn6': [(246, 239, 247), (208, 209, 230), (166, 189, 219), (103, 169, 207), (28, 144, 153), (1, 108, 89)],
    'pubugn7': [(246, 239, 247), (208, 209, 230), (166, 189, 219), (103, 169, 207), (54, 144, 192), (2, 129, 138), (1, 100, 80)],
    'pubugn8': [(255, 247, 251), (236, 226, 240), (208, 209, 230), (166, 189, 219), (103, 169, 207), (54, 144, 192), (2, 129, 138), (1, 100, 80)],
    'pubugn9': [(255, 247, 251), (236, 226, 240), (208, 209, 230), (166, 189, 219), (103, 169, 207), (54, 144, 192), (2, 129, 138), (1, 108, 89), (1, 70, 54)],
    'puor10': [(127, 59, 8), (45, 0, 75), (179, 88, 6), (224, 130, 20), (253, 184, 99), (254, 224, 182), (216, 218, 235), (178, 171, 210), (128, 115, 172), (84, 39, 136)],
    'puor11': [(127, 59, 8), (84, 39, 136), (45, 0, 75), (179, 88, 6), (224, 130, 20), (253, 184, 99), (254, 224, 182), (247, 247, 247), (216, 218, 235), (178, 171, 210), (128, 115, 172)],
    'puor3': [(241, 163, 64), (247, 247, 247), (153, 142, 195)],
    'puor4': [(230, 97, 1), (253, 184, 99), (178, 171, 210), (94, 60, 153)],
    'puor5': [(230, 97, 1), (253, 184, 99), (247, 247, 247), (178, 171, 210), (94, 60, 153)],
    'puor6': [(179, 88, 6), (241, 163, 64), (254, 224, 182), (216, 218, 235), (153, 142, 195), (84, 39, 136)],
    'puor7': [(179, 88, 6), (241, 163, 64), (254, 224, 182), (247, 247, 247), (216, 218, 235), (153, 142, 195), (84, 39, 136)],
    'puor8': [(179, 88, 6), (224, 130, 20), (253, 184, 99), (254, 224, 182), (216, 218, 235), (178, 171, 210), (128, 115, 172), (84, 39, 136)],
    'puor9': [(179, 88, 6), (224, 130, 20), (253, 184, 99), (254, 224, 182), (247, 247, 247), (216, 218, 235), (178, 171, 210), (128, 115, 172), (84, 39, 136)],
    'purd3': [(231, 225, 239), (201, 148, 199), (221, 28, 119)],
    'purd4': [(241, 238, 246), (215, 181, 216), (223, 101, 176), (206, 18, 86)],
    'purd5': [(241, 238, 246), (215, 181, 216), (223, 101, 176), (221, 28, 119), (152, 0, 67)],
    'purd6': [(241, 238, 246), (212, 185, 218), (201, 148, 199), (223, 101, 176), (221, 28, 119), (152, 0, 67)],
    'purd7': [(241, 238, 246), (212, 185, 218), (201, 148, 199), (223, 101, 176), (231, 41, 138), (206, 18, 86), (145, 0, 63)],
    'purd8': [(247, 244, 249), (231, 225, 239), (212, 185, 218), (201, 148, 199), (223, 101, 176), (231, 41, 138), (206, 18, 86), (145, 0, 63)],
    'purd9': [(247, 244, 249), (231, 225, 239), (212, 185, 218), (201, 148, 199), (223, 101, 176), (231, 41, 138), (206, 18, 86), (152, 0, 67), (103, 0, 31)],
    'purples3': [(239, 237, 245), (188, 189, 220), (117, 107, 177)],
    'purples4': [(242, 240, 247), (203, 201, 226), (158, 154, 200), (106, 81, 163)],
    'purples5': [(242, 240, 247), (203, 201, 226), (158, 154, 200), (117, 107, 177), (84, 39, 143)],
    'purples6': [(242, 240, 247), (218, 218, 235), (188, 189, 220), (158, 154, 200), (117, 107, 177), (84, 39, 143)],
    'purples7': [(242, 240, 247), (218, 218, 235), (188, 189, 220), (158, 154, 200), (128, 125, 186), (106, 81, 163), (74, 20, 134)],
    'purples8': [(252, 251, 253), (239, 237, 245), (218, 218, 235), (188, 189, 220), (158, 154, 200), (128, 125, 186), (106, 81, 163), (74, 20, 134)],
    'purples9': [(252, 251, 253), (239, 237, 245), (218, 218, 235), (188, 189, 220), (158, 154, 200), (128, 125, 186), (106, 81, 163), (84, 39, 143), (63, 0, 125)],
    'rdbu10': [(103, 0, 31), (5, 48, 97), (178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (209, 229, 240), (146, 197, 222), (67, 147, 195), (33, 102, 172)],
    'rdbu11': [(103, 0, 31), (33, 102, 172), (5, 48, 97), (178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (247, 247, 247), (209, 229, 240), (146, 197, 222), (67, 147, 195)],
    'rdbu3': [(239, 138, 98), (247, 247, 247), (103, 169, 207)],
    'rdbu4': [(202, 0, 32), (244, 165, 130), (146, 197, 222), (5, 113, 176)],
    'rdbu5': [(202, 0, 32), (244, 165, 130), (247, 247, 247), (146, 197, 222), (5, 113, 176)],
    'rdbu6': [(178, 24, 43), (239, 138, 98), (253, 219, 199), (209, 229, 240), (103, 169, 207), (33, 102, 172)],
    'rdbu7': [(178, 24, 43), (239, 138, 98), (253, 219, 199), (247, 247, 247), (209, 229, 240), (103, 169, 207), (33, 102, 172)],
    'rdbu8': [(178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (209, 229, 240), (146, 197, 222), (67, 147, 195), (33, 102, 172)],
    'rdbu9': [(178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (247, 247, 247), (209, 229, 240), (146, 197, 222), (67, 147, 195), (33, 102, 172)],
    'rdgy10': [(103, 0, 31), (26, 26, 26), (178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (224, 224, 224), (186, 186, 186), (135, 135, 135), (77, 77, 77)],
    'rdgy11': [(103, 0, 31), (77, 77, 77), (26, 26, 26), (178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (255, 255, 255), (224, 224, 224), (186, 186, 186), (135, 135, 135)],
    'rdgy3': [(239, 138, 98), (255, 255, 255), (153, 153, 153)],
    'rdgy4': [(202, 0, 32), (244, 165, 130), (186, 186, 186), (64, 64, 64)],
    'rdgy5': [(202, 0, 32), (244, 165, 130), (255, 255, 255), (186, 186, 186), (64, 64, 64)],
    'rdgy6': [(178, 24, 43), (239, 138, 98), (253, 219, 199), (224, 224, 224), (153, 153, 153), (77, 77, 77)],
    'rdgy7': [(178, 24, 43), (239, 138, 98), (253, 219, 199), (255, 255, 255), (224, 224, 224), (153, 153, 153), (77, 77, 77)],
    'rdgy8': [(178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (224, 224, 224), (186, 186, 186), (135, 135, 135), (77, 77, 77)],
    'rdgy9': [(178, 24, 43), (214, 96, 77), (244, 165, 130), (253, 219, 199), (255, 255, 255), (224, 224, 224), (186, 186, 186), (135, 135, 135), (77, 77, 77)],
    'rdpu3': [(253, 224, 221), (250, 159, 181), (197, 27, 138)],
    'rdpu4': [(254, 235, 226), (251, 180, 185), (247, 104, 161), (174, 1, 126)],
    'rdpu5': [(254, 235, 226), (251, 180, 185), (247, 104, 161), (197, 27, 138), (122, 1, 119)],
    'rdpu6': [(254, 235, 226), (252, 197, 192), (250, 159, 181), (247, 104, 161), (197, 27, 138), (122, 1, 119)],
    'rdpu7': [(254, 235, 226), (252, 197, 192), (250, 159, 181), (247, 104, 161), (221, 52, 151), (174, 1, 126), (122, 1, 119)],
    'rdpu8': [(255, 247, 243), (253, 224, 221), (252, 197, 192), (250, 159, 181), (247, 104, 161), (221, 52, 151), (174, 1, 126), (122, 1, 119)],
    'rdpu9': [(255, 247, 243), (253, 224, 221), (252, 197, 192), (250, 159, 181), (247, 104, 161), (221, 52, 151), (174, 1, 126), (122, 1, 119), (73, 0, 106)],
    'rdylbu10': [(165, 0, 38), (49, 54, 149), (215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 144), (224, 243, 248), (171, 217, 233), (116, 173, 209), (69, 117, 180)],
    'rdylbu11': [(165, 0, 38), (69, 117, 180), (49, 54, 149), (215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 144), (255, 255, 191), (224, 243, 248), (171, 217, 233), (116, 173, 209)],
    'rdylbu3': [(252, 141, 89), (255, 255, 191), (145, 191, 219)],
    'rdylbu4': [(215, 25, 28), (253, 174, 97), (171, 217, 233), (44, 123, 182)],
    'rdylbu5': [(215, 25, 28), (253, 174, 97), (255, 255, 191), (171, 217, 233), (44, 123, 182)],
    'rdylbu6': [(215, 48, 39), (252, 141, 89), (254, 224, 144), (224, 243, 248), (145, 191, 219), (69, 117, 180)],
    'rdylbu7': [(215, 48, 39), (252, 141, 89), (254, 224, 144), (255, 255, 191), (224, 243, 248), (145, 191, 219), (69, 117, 180)],
    'rdylbu8': [(215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 144), (224, 243, 248), (171, 217, 233), (116, 173, 209), (69, 117, 180)],
    'rdylbu9': [(215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 144), (255, 255, 191), (224, 243, 248), (171, 217, 233), (116, 173, 209), (69, 117, 180)],
    'rdylgn10': [(165, 0, 38), (0, 104, 55), (215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 139), (217, 239, 139), (166, 217, 106), (102, 189, 99), (26, 152, 80)],
    'rdylgn11': [(165, 0, 38), (26, 152, 80), (0, 104, 55), (215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 139), (255, 255, 191), (217, 239, 139), (166, 217, 106), (102, 189, 99)],
    'rdylgn3': [(252, 141, 89), (255, 255, 191), (145, 207, 96)],
    'rdylgn4': [(215, 25, 28), (253, 174, 97), (166, 217, 106), (26, 150, 65)],
    'rdylgn5': [(215, 25, 28), (253, 174, 97), (255, 255, 191), (166, 217, 106), (26, 150, 65)],
    'rdylgn6': [(215, 48, 39), (252, 141, 89), (254, 224, 139), (217, 239, 139), (145, 207, 96), (26, 152, 80)],
    'rdylgn7': [(215, 48, 39), (252, 141, 89), (254, 224, 139), (255, 255, 191), (217, 239, 139), (145, 207, 96), (26, 152, 80)],
    'rdylgn8': [(215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 139), (217, 239, 139), (166, 217, 106), (102, 189, 99), (26, 152, 80)],
    'rdylgn9': [(215, 48, 39), (244, 109, 67), (253, 174, 97), (254, 224, 139), (255, 255, 191), (217, 239, 139), (166, 217, 106), (102, 189, 99), (26, 152, 80)],
    'reds3': [(254, 224, 210), (252, 146, 114), (222, 45, 38)],
    'reds4': [(254, 229, 217), (252, 174, 145), (251, 106, 74), (203, 24, 29)],
    'reds5': [(254, 229, 217), (252, 174, 145), (251, 106, 74), (222, 45, 38), (165, 15, 21)],
    'reds6': [(254, 229, 217), (252, 187, 161), (252, 146, 114), (251, 106, 74), (222, 45, 38), (165, 15, 21)],
    'reds7': [(254, 229, 217), (252, 187, 161), (252, 146, 114), (251, 106, 74), (239, 59, 44), (203, 24, 29), (153, 0, 13)],
    'reds8': [(255, 245, 240), (254, 224, 210), (252, 187, 161), (252, 146, 114), (251, 106, 74), (239, 59, 44), (203, 24, 29), (153, 0, 13)],
    'reds9': [(255, 245, 240), (254, 224, 210), (252, 187, 161), (252, 146, 114), (251, 106, 74), (239, 59, 44), (203, 24, 29), (165, 15, 21), (103, 0, 13)],
    'set13': [(228, 26, 28), (55, 126, 184), (77, 175, 74)],
    'set14': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163)],
    'set15': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163), (255, 127, 0)],
    'set16': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163), (255, 127, 0), (255, 255, 51)],
    'set17': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163), (255, 127, 0), (255, 255, 51), (166, 86, 40)],
    'set18': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163), (255, 127, 0), (255, 255, 51), (166, 86, 40), (247, 129, 191)],
    'set19': [(228, 26, 28), (55, 126, 184), (77, 175, 74), (152, 78, 163), (255, 127, 0), (255, 255, 51), (166, 86, 40), (247, 129, 191), (153, 153, 153)],
    'set23': [(102, 194, 165), (252, 141, 98), (141, 160, 203)],
    'set24': [(102, 194, 165), (252, 141, 98), (141, 160, 203), (231, 138, 195)],
    'set25': [(102, 194, 165), (252, 141, 98), (141, 160, 203), (231, 138, 195), (166, 216, 84)],
    'set26': [(102, 194, 165), (252, 141, 98), (141, 160, 203), (231, 138, 195), (166, 216, 84), (255, 217, 47)],
    'set27': [(102, 194, 165), (252, 141, 98), (141, 160, 203), (231, 138, 195), (166, 216, 84), (255, 217, 47), (229, 196, 148)],
    'set28': [(102, 194, 165), (252, 141, 98), (141, 160, 203), (231, 138, 195), (166, 216, 84), (255, 217, 47), (229, 196, 148), (179, 179, 179)],
    'set310': [(141, 211, 199), (188, 128, 189), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105), (252, 205, 229), (217, 217, 217)],
    'set311': [(141, 211, 199), (188, 128, 189), (204, 235, 197), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105), (252, 205, 229), (217, 217, 217)],
    'set312': [(141, 211, 199), (188, 128, 189), (204, 235, 197), (255, 237, 111), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105), (252, 205, 229), (217, 217, 217)],
    'set33': [(141, 211, 199), (255, 255, 179), (190, 186, 218)],
    'set34': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114)],
    'set35': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211)],
    'set36': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98)],
    'set37': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105)],
    'set38': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105), (252, 205, 229)],
    'set39': [(141, 211, 199), (255, 255, 179), (190, 186, 218), (251, 128, 114), (128, 177, 211), (253, 180, 98), (179, 222, 105), (252, 205, 229), (217, 217, 217)],
    'spectral10': [(158, 1, 66), (94, 79, 162), (213, 62, 79), (244, 109, 67), (253, 174, 97), (254, 224, 139), (230, 245, 152), (171, 221, 164), (102, 194, 165), (50, 136, 189)],
    'spectral11': [(158, 1, 66), (50, 136, 189), (94, 79, 162), (213, 62, 79), (244, 109, 67), (253, 174, 97), (254, 224, 139), (255, 255, 191), (230, 245, 152), (171, 221, 164), (102, 194, 165)],
    'spectral3': [(252, 141, 89), (255, 255, 191), (153, 213, 148)],
    'spectral4': [(215, 25, 28), (253, 174, 97), (171, 221, 164), (43, 131, 186)],
    'spectral5': [(215, 25, 28), (253, 174, 97), (255, 255, 191), (171, 221, 164), (43, 131, 186)],
    'spectral6': [(213, 62, 79), (252, 141, 89), (254, 224, 139), (230, 245, 152), (153, 213, 148), (50, 136, 189)],
    'spectral7': [(213, 62, 79), (252, 141, 89), (254, 224, 139), (255, 255, 191), (230, 245, 152), (153, 213, 148), (50, 136, 189)],
    'spectral8': [(213, 62, 79), (244, 109, 67), (253, 174, 97), (254, 224, 139), (230, 245, 152), (171, 221, 164), (102, 194, 165), (50, 136, 189)],
    'spectral9': [(213, 62, 79), (244, 109, 67), (253, 174, 97), (254, 224, 139), (255, 255, 191), (230, 245, 152), (171, 221, 164), (102, 194, 165), (50, 136, 189)],
    'ylgn3': [(247, 252, 185), (173, 221, 142), (49, 163, 84)],
    'ylgn4': [(255, 255, 204), (194, 230, 153), (120, 198, 121), (35, 132, 67)],
    'ylgn5': [(255, 255, 204), (194, 230, 153), (120, 198, 121), (49, 163, 84), (0, 104, 55)],
    'ylgn6': [(255, 255, 204), (217, 240, 163), (173, 221, 142), (120, 198, 121), (49, 163, 84), (0, 104, 55)],
    'ylgn7': [(255, 255, 204), (217, 240, 163), (173, 221, 142), (120, 198, 121), (65, 171, 93), (35, 132, 67), (0, 90, 50)],
    'ylgn8': [(255, 255, 229), (247, 252, 185), (217, 240, 163), (173, 221, 142), (120, 198, 121), (65, 171, 93), (35, 132, 67), (0, 90, 50)],
    'ylgn9': [(255, 255, 229), (247, 252, 185), (217, 240, 163), (173, 221, 142), (120, 198, 121), (65, 171, 93), (35, 132, 67), (0, 104, 55), (0, 69, 41)],
    'ylgnbu3': [(237, 248, 177), (127, 205, 187), (44, 127, 184)],
    'ylgnbu4': [(255, 255, 204), (161, 218, 180), (65, 182, 196), (34, 94, 168)],
    'ylgnbu5': [(255, 255, 204), (161, 218, 180), (65, 182, 196), (44, 127, 184), (37, 52, 148)],
    'ylgnbu6': [(255, 255, 204), (199, 233, 180), (127, 205, 187), (65, 182, 196), (44, 127, 184), (37, 52, 148)],
    'ylgnbu7': [(255, 255, 204), (199, 233, 180), (127, 205, 187), (65, 182, 196), (29, 145, 192), (34, 94, 168), (12, 44, 132)],
    'ylgnbu8': [(255, 255, 217), (237, 248, 177), (199, 233, 180), (127, 205, 187), (65, 182, 196), (29, 145, 192), (34, 94, 168), (12, 44, 132)],
    'ylgnbu9': [(255, 255, 217), (237, 248, 177), (199, 233, 180), (127, 205, 187), (65, 182, 196), (29, 145, 192), (34, 94, 168), (37, 52, 148), (8, 29, 88)],
    'ylorbr3': [(255, 247, 188), (254, 196, 79), (217, 95, 14)],
    'ylorbr4': [(255, 255, 212), (254, 217, 142), (254, 153, 41), (204, 76, 2)],
    'ylorbr5': [(255, 255, 212), (254, 217, 142), (254, 153, 41), (217, 95, 14), (153, 52, 4)],
    'ylorbr6': [(255, 255, 212), (254, 227, 145), (254, 196, 79), (254, 153, 41), (217, 95, 14), (153, 52, 4)],
    'ylorbr7': [(255, 255, 212), (254, 227, 145), (254, 196, 79), (254, 153, 41), (236, 112, 20), (204, 76, 2), (140, 45, 4)],
    'ylorbr8': [(255, 255, 229), (255, 247, 188), (254, 227, 145), (254, 196, 79), (254, 153, 41), (236, 112, 20), (204, 76, 2), (140, 45, 4)],
    'ylorbr9': [(255, 255, 229), (255, 247, 188), (254, 227, 145), (254, 196, 79), (254, 153, 41), (236, 112, 20), (204, 76, 2), (153, 52, 4), (102, 37, 6)],
    'ylorrd3': [(255, 237, 160), (254, 178, 76), (240, 59, 32)],
    'ylorrd4': [(255, 255, 178), (254, 204, 92), (253, 141, 60), (227, 26, 28)],
    'ylorrd5': [(255, 255, 178), (254, 204, 92), (253, 141, 60), (240, 59, 32), (189, 0, 38)],
    'ylorrd6': [(255, 255, 178), (254, 217, 118), (254, 178, 76), (253, 141, 60), (240, 59, 32), (189, 0, 38)],
    'ylorrd7': [(255, 255, 178), (254, 217, 118), (254, 178, 76), (253, 141, 60), (252, 78, 42), (227, 26, 28), (177, 0, 38)],
    'ylorrd8': [(255, 255, 204), (255, 237, 160), (254, 217, 118), (254, 178, 76), (253, 141, 60), (252, 78, 42), (227, 26, 28), (177, 0, 38)],
}


if __name__ == '__main__':
    main()
