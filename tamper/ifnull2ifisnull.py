#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

def tamper(value):
    """
    Replaces 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'
    Example: 'IFNULL(1, 2)' becomes 'IF(ISNULL(1), 2, 1)'
    """

    if value and value.find("IFNULL") > -1:

        while value.find("IFNULL(") > -1:
            index = value.find("IFNULL(")
            deepness = 1
            comma, end = None, None

            for i in xrange(index + len("IFNULL("), len(value)):
                if deepness == 1 and value[i] == ',':
                    comma = i

                elif deepness == 1 and value[i] == ')':
                    end = i
                    break

                elif value[i] == '(':
                    deepness += 1

                elif value[i] == ')':
                    deepness -= 1

            if comma and end:
                A = value[index + len("IFNULL("):comma]
                B = value[comma + 1:end]
                newVal = "IF(ISNULL(%s),%s,%s)" % (A, B, A)
                value = value[:index] + newVal + value[end+1:]
            else:
                break

    return value
