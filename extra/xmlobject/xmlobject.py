#!/usr/bin/env python
#
# Copyright 2007-2008 David McNab
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

"""
Allows XML files to be operated on like Python objects.

Features:
    - load XML source from file pathnames, readable file objects or raw strings
    - add, get and set tag attributes like with python attributes
    - iterate over nodes
    - save the modified XMLFile or XMLObject to file

Example XML file::

    <?xml version="1.0" encoding="UTF-8"?>
    <rapsheets>
     <person name="John Smith" age="42">
        <!-- John Smith has an appeal in process against his last conviction -->
        <crime name="Armed robbery" date="March 11, 1994"/>
        <crime name="Aggravated burglary" date="June 9, 2001"/>
     </person>
     <person name="Mary Jones" age="33">
        <crime name="Prostitution" date="January 8, 1997"/>
        <crime name="Selling heroin" date="September 4, 2002"/>
        <crime name="Manslaughter" date="December 21, 2004"/>
     </person>
    </rapsheets>

Example usage::

    >> from xmlobject import XMLFile

    >> x = XMLFile(path="sample.xml")

    >> print x
    <xmlobj.XMLFile instance at 0xb7ccc52c>

    >> print x.root
    <XMLNode: rapsheets>

    >> print x.root._children
    [<XMLNode: text>, <XMLNode: person>, <XMLNode: text>,
     <XMLNode: person>, <XMLNode: text>]

    >> print x.root.person
    [<XMLNode: person>, <XMLNode: person>]

    >> print x.root.person[0].name
    John Smith

    >> john = x.root.person[0]

    >> john.height = 184

    >> c = john._addNode("crime")

    >> c.name = "Grand Theft Auto"

    >> c.date = "4 May, 2005"

    >> print x.toxml()
    <?xml version="1.0" ?>
    <rapsheets>
     <person age="42" height="184" name="John Smith">
        <!-- John Smith has an appeal in process against his last conviction -->
        <crime date="March 11, 1994" name="Armed robbery"/>
        <crime date="June 9, 2001" name="Aggravated burglary"/>
     <crime date="4 May, 2005" name="Grand Theft Auto"/></person>
     <person age="33" name="Mary Jones">
        <crime date="January 8, 1997" name="Prostitution"/>
        <crime date="September 4, 2002" name="Selling heroin"/>
        <crime date="December 21, 2004" name="Manslaughter"/>
     </person>
    </rapsheets>

    >>

"""

import sys, os
import xml.dom
import xml.dom.minidom
from xml.dom.minidom import parse, parseString, getDOMImplementation

impl = getDOMImplementation()

class MissingRootTag(Exception):
    """root tag name was not given"""

class InvalidXML(Exception):
    """failed to parse XML input"""

class CannotSave(Exception):
    """unable to save"""

class InvalidNode(Exception):
    """not a valid minidom node"""

class XMLFile:
    """
    Allows an xml file to be viewed and operated on
    as a python object.

    (If you're viewing the epydoc-generated HTML documentation, click the 'show private'
    link at the top right of this page to see all the methods)

    Holds the root node in the .root attribute, also in an attribute
    with the same name as this root node.
    """
    def __init__(self, **kw):
        """
        Create an XMLFile

        Keywords:
            - path - a pathname from which the file can be read
            - file - an open file object from which the raw xml
              can be read
            - raw - the raw xml itself
            - root - name of root tag, if not reading content

        Usage scenarios:
            1. Working with existing content - you must supply input in
               one of the following ways:
                   - 'path' must be an existing file, or
                   - 'file' must be a readable file object, or
                   - 'raw' must contain raw xml as a string
            2. Creating whole new content - you must give the name
               of the root tag in the 'root' keyword

        Notes:
            - Keyword precedence governing existing content is:
                1. path (if existing file)
                2. file
                3. raw
            - If working with existing content:
                - if the 'root' is given, then the content's toplevel tag
                  MUST match the value given for 'root'
                - trying to _save will raise an exception unless 'path'
                  has been given
            - if not working with existing content:
                - 'root' must be given
                - _save() will raise an exception unless 'path' has been given
        """
        path = kw.get("path", None)
        fobj = kw.get("file", None)
        raw = kw.get("raw", None)
        root = kw.get("root", None)
        textfilter = kw.get("textfilter", None)

        if path:
            self.path = path
            try:
                fobj = file(path)
            except IOError:
                pass
        else:
            self.path = None

        if fobj:
            raw = fobj.read()

        if raw:
            self.dom = xml.dom.minidom.parseString(raw)
        else:
            # could not source content, so create a blank slate
            if not root:
                # in which case, must give a root node name
                raise MissingRootTag(
                        "No existing content, so must specify root")

            # ok, create a blank dom
            self.dom = impl.createDocument(None, root, None)

        # get the root node, save it as attributes 'root' and name of node
        rootnode = self.dom.documentElement

        # now validate root tag
        if root:
            if rootnode.nodeName != root:
                raise IncorrectRootTag("Gave root='%s', input has root='%s'" % (
                    root, rootnode.nodeName))

        if textfilter:
            self.textfilter = textfilter
        else:
            self.textfilter = lambda x: x

        # need this for recursion in XMLNode
        self._childrenByName = {}
        self._children = []

        # add all the child nodes
        for child in self.dom.childNodes:
            childnode = XMLNode(self, child)
            #print "compare %s to %s" % (rootnode, child)
            if child == rootnode:
                #print "found root"
                self.root = childnode
        setattr(self, rootnode.nodeName, self.root)

    def save(self, where=None, obj=None):
        """
        Saves the document.

        If argument 'where' is given, saves to it, otherwise
        tries to save to the original given 'path' (or barfs)

        Value can be a string (taken to be a file path), or an open
        file object.
        """
        obj = obj or self.dom

        if not where:
            if self._root.path:
                where = self._root.path

        if isinstance(where, str):
            where = file(where, "w")

        if not where:
            raise CannotSave("No save destination, and no original path")

        where.write(obj.toxml())
        where.flush()

    def saveAs(self, path):
        """
        save this time, and all subsequent times, to filename 'path'
        """
        self.path = path
        self.save()

    def toxml(self):
        return self.dom.toxml()

    def __len__(self):
        """
        returns number of child nodes
        """
        return len(self._children)

    def __getitem__(self, idx):
        if isinstance(idx, int):
            return self._children[idx]
        else:
            return self._childrenByName[idx]


class XMLNode:
    """
    This is the workhorse for the xml object interface

    (If you're viewing the epydoc-generated HTML documentation, click the 'show private'
    link at the top right of this page to see all the methods)

    """
    def __init__(self, parent, node):
        """
        You shouldn't need to instantiate this directly
        """
        self._parent = parent
        if isinstance(parent, XMLFile):
            self._root = parent
        else:
            self._root = parent._root
        self._node = node
        self._childrenByName = {}
        self._children = []

        # add ourself to parent's children registry
        parent._children.append(self)

        # the deal with named subtags is that we store the first instance
        # as itself, and with second and subsequent instances, we make a list
        parentDict = self._parent._childrenByName
        nodeName = node.nodeName
        if not parentDict.has_key(nodeName):
            parentDict[nodeName] = parent.__dict__[nodeName] = self
        else:
            if isinstance(parentDict[nodeName], XMLNode):
                # this is the second child node of a given tag name, so convert
                # the instance to a list
                parentDict[nodeName] = parent.__dict__[nodeName] = [parentDict[nodeName]]
            parentDict[nodeName].append(self)

        # figure out our type
        self._value = None
        if isinstance(node, xml.dom.minidom.Text):
            self._type = "text"
            self._value = self._root.textfilter(node.nodeValue)
        elif isinstance(node, xml.dom.minidom.Element):
            self._type = "node"
        elif isinstance(node, xml.dom.minidom.Comment):
            self._type = "comment"
            self._value = node.nodeValue
        else:
            raise InvalidNode("node class %s" % node.__class__)

        # and wrap all the child nodes
        for child in node.childNodes:
            XMLNode(self, child)

    def _render(self):
        """
        Produces well-formed XML of this node's contents,
        indented as required
        """
        return self._node.toxml()

    def __repr__(self):
        if self._type == "node":
            return "<XMLNode: %s>" % self._node.nodeName
        else:
            return "<XMLNode: %s>" % self._type

    def __getattr__(self, attr):
        """
        Fetches an attribute or child node of this tag

        If it's an attribute, then returns the attribute value as a string.

        If a child node, then:
            - if there is only one child node of that name, return it
            - if there is more than one child node of that name, return a list
              of child nodes of that tag name

        Supports some magic attributes:
            - _text - the value of the first child node of type text
        """
        #print "%s: __getattr__: attr=%s" % (self, attr)

        if attr == '_text':
            # magic attribute to return text
            tnode = self['#text']
            if isinstance(tnode, list):
                tnode = tnode[0]
            return tnode._value

        if self._type in ['text', 'comment']:
            if attr == '_value':
                return self._node.nodeValue
            else:
                raise AttributeError(attr)

        if self._node.hasAttribute(attr):
            return self._node.getAttribute(attr)
        elif self._childrenByName.has_key(attr):
            return self._childrenByName[attr]

        #elif attr == 'value':
            # magic attribute

        else:
            raise AttributeError(attr)


    def __setattr__(self, attr, val):
        """
        Change the value of an attribute of this tag

        The magic attribute '_text' can be used to set the first child
        text node's value

        For example::

            Consider:

              <somenode>
                <child>foo</child>
              </somenode>

            >> somenode
            <XMLNODE: somenode>
            >> somenode.child
            <XMLNODE: child>
            >> somenode.child._text
            'foo'
            >> somenode._toxml()
            u'<somenode><child>foo</child></somenode>'
            >> somenode.child._text = 'bar'
            >> somenode.child._text
            'bar'
            >> somenode.child._toxml()
            u'<somenode><child>bar/child></somenode>'

        """
        if attr.startswith("_"):

            # magic attribute for setting _text
            if attr == '_text':
                tnode = self['#text']
                if isinstance(tnode, list):
                    tnode = tnode[0]
                tnode._node.nodeValue = val
                tnode._value = val
                return

            self.__dict__[attr] = val
        elif self._type in ['text', 'comment']:
            self._node.nodeValue = val
        else:
            # discern between attribute and child node
            if self._childrenByName.has_key(attr):
                raise Exception("Attribute Exists")
            self._node.setAttribute(attr, str(val))

    def _keys(self):
        """
        Return a list of attribute names
        """
        return self._node.attributes.keys()

    def _values(self):
        """
        Returns a list of (attrname, attrval) tuples for this tag
        """
        return [self._node.getAttribute(k) for k in self._node.attributes.keys()]

    def _items(self):
        """
        returns a list of attribute values for this tag
        """
        return [(k, self._node.getAttribute(k)) for k in self._node.attributes.keys()]

    def _has_key(self, k):
        """
        returns True if this tag has an attribute of the given name
        """
        return self._node.hasAttribute(k) or self._childrenByName.has_key(k)

    def _get_name(self):
        if self._type == "node":
            return self._node.nodeName
        else:
            return self._type

    def _get(self, k, default=None):
        """
        returns the value of attribute k, or default if no such attribute
        """
        if self._has_key(k):
            return getattr(self, k)
        else:
            return default

    def __len__(self):
        """
        returns number of child nodes
        """
        return len(self._children)

    def __getitem__(self, idx):
        """
        if given key is numeric, return the nth child, otherwise
        try to return the child tag (or list of child tags) having
        the key as the tag name
        """
        #print "__getitem__: idx=%s" % str(idx)

        if isinstance(idx, slice) or isinstance(idx, int):
            return self._children[idx]
        elif isinstance(idx, str):
            return self._childrenByName[idx]
        else:
            raise IndexError(idx)

    def _addNode(self, child):
        """
        Tries to append a child node to the tree, and returns it

        Value of 'child' must be one of:
            - a string (in which case it is taken to be the name
              of the new node's tag)
            - a dom object, in which case it will be wrapped and added
            - an XMLNode object, in which case it will be added without
              wrapping
        """

        if isinstance(child, XMLNode):

            # add it to our children registry
            self._children.append(child)

            parentDict = self._childrenByName
            nodeName = child._node.nodeName

            if not parentDict.has_key(nodeName):
                parentDict[nodeName] = parent.__dict__[nodeName] = child
            else:
                if isinstance(parentDict[nodeName], XMLNode):
                    # this is the second child node of a given tag name, so convert
                    # the instance to a list
                    parentDict[nodeName] = self.__dict__[nodeName] = [parentDict[nodeName]]
                parentDict[nodeName].append(child)

            # and stick it in the dom
            self._node.appendChild(child._node)

            return child

        elif isinstance(child, str):
            childNode = self._root.dom.createElement(child)
            self._node.appendChild(childNode)

        elif isinstance(child, xml.dom.minidom.Element):
            childNode = child
            child = childNode.nodeName
            self._node.appendChild(childNode)


        return XMLNode(self, childNode)

    def _addText(self, value):
        """
        Tries to append a child text node, with the given text, to the tree,
        and returns the created node object
        """
        childNode = self._root.dom.createTextNode(value)
        self._node.appendChild(childNode)
        return XMLNode(self, childNode)

    def _addComment(self, comment):
        """
        Tries to append a child comment node (with the given text value)
        to the tree, and returns the create node object
        """
        childNode = self._root.dom.createCommentNode(comment)
        self._node.appendChild(childNode)
        return XMLNode(self, childNode)

    def _save(self, where=None):
        """
        Generates well-formed XML from just this node, and saves it
        to a file.

        Argument 'where' is either an open file object, or a pathname

        If 'where' is not given, then saves the entire document tree.
        """
        if not where:
            self._root.save()
        else:
            self._root.save(where, self._node)

    def _toxml(self):
        """
        renders just this node out to raw xml code
        """
        return self._node.toxml()

    def _treeWalker(self, node, nodes):
        for child in node._children:
            if child._type == 'node':
                nodes.append(child)
                self._treeWalker(child, nodes)

    def _toflat(self):
        ret = [self]
        self._treeWalker(self, ret)
        return ret

    _name = property(_get_name)
