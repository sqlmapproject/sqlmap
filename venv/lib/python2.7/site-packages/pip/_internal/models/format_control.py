from pip._vendor.packaging.utils import canonicalize_name


class FormatControl(object):
    """A helper class for controlling formats from which packages are installed.
    If a field is falsy, it isn't set. If it is {':all:'}, it should match all
    packages except those listed in the other field. Only one field can be set
    to {':all:'} at a time. The rest of the time exact package name matches
    are listed, with any given package only showing up in one field at a time.
    """
    def __init__(self, no_binary=None, only_binary=None):
        self.no_binary = set() if no_binary is None else no_binary
        self.only_binary = set() if only_binary is None else only_binary

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "{}({}, {})".format(
            self.__class__.__name__,
            self.no_binary,
            self.only_binary
        )

    @staticmethod
    def handle_mutual_excludes(value, target, other):
        new = value.split(',')
        while ':all:' in new:
            other.clear()
            target.clear()
            target.add(':all:')
            del new[:new.index(':all:') + 1]
            # Without a none, we want to discard everything as :all: covers it
            if ':none:' not in new:
                return
        for name in new:
            if name == ':none:':
                target.clear()
                continue
            name = canonicalize_name(name)
            other.discard(name)
            target.add(name)

    def get_allowed_formats(self, canonical_name):
        result = {"binary", "source"}
        if canonical_name in self.only_binary:
            result.discard('source')
        elif canonical_name in self.no_binary:
            result.discard('binary')
        elif ':all:' in self.only_binary:
            result.discard('source')
        elif ':all:' in self.no_binary:
            result.discard('binary')
        return frozenset(result)

    def disallow_binaries(self):
        self.handle_mutual_excludes(
            ':all:', self.no_binary, self.only_binary,
        )
