import re

#not finished (watch for number of parenthesis)
#IFNULL(A,B) -> IF(ISNULL(A),B,A)
def tamper(place, value):
    if value:
        if value.find("IFNULL") > -1:
            import pdb
            pdb.set_trace()
        value = re.sub(r"IFNULL(\(|%28)(?P<A>.+?)(,|%2C)(?P<B>.+?)(\)|%29)", lambda match: "IF%%28ISNULL%%28%s%%29%%2C%s%%2C%s%%29" % ("A="+match.group("A"), "B="+match.group("B"), "A="+match.group("A")), value)
    return value
