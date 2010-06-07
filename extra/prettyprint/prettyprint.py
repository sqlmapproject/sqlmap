#!/usr/bin/env python

#Copyright (c) 2010, Miroslav Stampar <miroslav.stampar@gmail.com>
#Added formatXML method

#Copyright (c) 2010, Chris Hall <chris.hall@mod10.net>
#All rights reserved.

#Redistribution and use in source and binary forms, with or without modification,
#are permitted provided that the following conditions are met:

#* Redistributions of source code must retain the above copyright notice,
#this list of conditions and the following disclaimer.
#* Redistributions in binary form must reproduce the above copyright notice,
#this list of conditions and the following disclaimer in the documentation
#and/or other materials provided with the distribution.

#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from xml.dom import minidom
from xml.dom import Node

def format(text):
        doc = minidom.parseString(text)
        root = doc.childNodes[0]
        return root.toprettyxml(indent='  ')

def formatXML(doc, encoding=None):
        root = doc.childNodes[0]
        return root.toprettyxml(indent='  ', encoding=encoding)

def _patch_minidom():
        minidom.Text.writexml = _writexml_text
        minidom.Element.writexml = _writexml_element
        minidom.Node.toprettyxml = _toprettyxml_node
        
def _collapse(node):
        for child in node.childNodes:
                if child.nodeType == Node.TEXT_NODE and len(child.data.strip()) == 0:
                        child.data = ''
                else:
                        _collapse(child)

def _writexml_text(self, writer, indent="", addindent="", newl=""):
        minidom._write_data(writer, "%s"%(self.data.strip()))
        
def _writexml_element(self, writer, indent="", addindent="", newl=""):
        # indent = current indentation
        # addindent = indentation to add to higher levels
        # newl = newline string
        writer.write(indent+"<" + self.tagName)
        
        attrs = self._get_attributes()
        a_names = attrs.keys()
        a_names.sort()
        
        for a_name in a_names:
                writer.write(" %s=\"" % a_name)
                minidom._write_data(writer, attrs[a_name].value)
                writer.write("\"")
        if self.childNodes:
                if self.childNodes[0].nodeType == Node.TEXT_NODE and len(self.childNodes[0].data) > 0:
                        writer.write(">")
                else:
                        writer.write(">%s"%(newl))
                for node in self.childNodes:
                        node.writexml(writer,indent+addindent,addindent,newl)
                if self.childNodes[-1].nodeType == Node.TEXT_NODE and len(self.childNodes[0].data) > 0:
                        writer.write("</%s>%s" % (self.tagName,newl))
                else:
                        writer.write("%s</%s>%s" % (indent,self.tagName,newl))
        else:
                writer.write("/>%s"%(newl))
                
def _toprettyxml_node(self, indent="\t", newl="\n", encoding = None):
        _collapse(self)
        # indent = the indentation string to prepend, per level
        # newl = the newline string to append
        writer = minidom._get_StringIO()
        if encoding is not None:
                import codecs
                # Can't use codecs.getwriter to preserve 2.0 compatibility
                writer = codecs.lookup(encoding)[3](writer)
        if self.nodeType == Node.DOCUMENT_NODE:
                # Can pass encoding only to document, to put it into XML header
                self.writexml(writer, "", indent, newl, encoding)
        else:
                self.writexml(writer, "", indent, newl)
        return writer.getvalue()

_patch_minidom()
