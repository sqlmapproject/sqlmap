def tamper(place, value):
    print "Hi, World!"
    print value
    if place=="GET" and value:
        value=value.upper()
    return value
