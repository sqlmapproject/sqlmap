#!/usr/bin/env python
# -*- mode:python; tab-width: 2; coding: utf-8 -*-

"""Partially backported python ABC classes"""

from __future__ import absolute_import

import sys
import types

if sys.version_info > (2, 6):
    raise ImportError("Use native ABC classes istead of this one.")


# Instance of old-style class
class _C:
    pass

_InstanceType = type(_C())


def abstractmethod(funcobj):
    """A decorator indicating abstract methods.

    Requires that the metaclass is ABCMeta or derived from it.  A
    class that has a metaclass derived from ABCMeta cannot be
    instantiated unless all of its abstract methods are overridden.
    The abstract methods can be called using any of the normal
    'super' call mechanisms.

    Usage:

        class C:
            __metaclass__ = ABCMeta
            @abstractmethod
            def my_abstract_method(self, ...):
                ...
    """
    funcobj.__isabstractmethod__ = True
    return funcobj


class ABCMeta(type):

    """Metaclass for defining Abstract Base Classes (ABCs).

    Use this metaclass to create an ABC.  An ABC can be subclassed
    directly, and then acts as a mix-in class.  You can also register
    unrelated concrete classes (even built-in classes) and unrelated
    ABCs as 'virtual subclasses' -- these and their descendants will
    be considered subclasses of the registering ABC by the built-in
    issubclass() function, but the registering ABC won't show up in
    their MRO (Method Resolution Order) nor will method
    implementations defined by the registering ABC be callable (not
    even via super()).

    """

    # A global counter that is incremented each time a class is
    # registered as a virtual subclass of anything.  It forces the
    # negative cache to be cleared before its next use.
    _abc_invalidation_counter = 0

    def __new__(mcls, name, bases, namespace):
        cls = super(ABCMeta, mcls).__new__(mcls, name, bases, namespace)
        # Compute set of abstract method names
        abstracts = set(name
                     for name, value in namespace.items()
                     if getattr(value, "__isabstractmethod__", False))
        for base in bases:
            for name in getattr(base, "__abstractmethods__", set()):
                value = getattr(cls, name, None)
                if getattr(value, "__isabstractmethod__", False):
                    abstracts.add(name)
        cls.__abstractmethods__ = frozenset(abstracts)
        # Set up inheritance registry
        cls._abc_registry = set()
        cls._abc_cache = set()
        cls._abc_negative_cache = set()
        cls._abc_negative_cache_version = ABCMeta._abc_invalidation_counter
        return cls

    def register(cls, subclass):
        """Register a virtual subclass of an ABC."""
        if not isinstance(subclass, (type, types.ClassType)):
            raise TypeError("Can only register classes")
        if issubclass(subclass, cls):
            return  # Already a subclass
        # Subtle: test for cycles *after* testing for "already a subclass";
        # this means we allow X.register(X) and interpret it as a no-op.
        if issubclass(cls, subclass):
            # This would create a cycle, which is bad for the algorithm below
            raise RuntimeError("Refusing to create an inheritance cycle")
        cls._abc_registry.add(subclass)
        ABCMeta._abc_invalidation_counter += 1  # Invalidate negative cache

    def _dump_registry(cls, file=None):
        """Debug helper to print the ABC registry."""
        print >> file, "Class: %s.%s" % (cls.__module__, cls.__name__)
        print >> file, "Inv.counter: %s" % ABCMeta._abc_invalidation_counter
        for name in sorted(cls.__dict__.keys()):
            if name.startswith("_abc_"):
                value = getattr(cls, name)
                print >> file, "%s: %r" % (name, value)

    def __instancecheck__(cls, instance):
        """Override for isinstance(instance, cls)."""
        # Inline the cache checking when it's simple.
        subclass = getattr(instance, '__class__', None)
        if subclass in cls._abc_cache:
            return True
        subtype = type(instance)
        # Old-style instances
        if subtype is _InstanceType:
            subtype = subclass
        if subtype is subclass or subclass is None:
            if (cls._abc_negative_cache_version ==
                ABCMeta._abc_invalidation_counter and
                subtype in cls._abc_negative_cache):
                return False
            # Fall back to the subclass check.
            return cls.__subclasscheck__(subtype)
        return (cls.__subclasscheck__(subclass) or
                cls.__subclasscheck__(subtype))

    def __subclasscheck__(cls, subclass):
        """Override for issubclass(subclass, cls)."""
        # Check cache
        if subclass in cls._abc_cache:
            return True
        # Check negative cache; may have to invalidate
        if cls._abc_negative_cache_version < ABCMeta._abc_invalidation_counter:
            # Invalidate the negative cache
            cls._abc_negative_cache = set()
            cls._abc_negative_cache_version = ABCMeta._abc_invalidation_counter
        elif subclass in cls._abc_negative_cache:
            return False
        # Check the subclass hook
        ok = cls.__subclasshook__(subclass)
        if ok is not NotImplemented:
            assert isinstance(ok, bool)
            if ok:
                cls._abc_cache.add(subclass)
            else:
                cls._abc_negative_cache.add(subclass)
            return ok
        # Check if it's a direct subclass
        if cls in getattr(subclass, '__mro__', ()):
            cls._abc_cache.add(subclass)
            return True
        # Check if it's a subclass of a registered class (recursive)
        for rcls in cls._abc_registry:
            if issubclass(subclass, rcls):
                cls._abc_cache.add(subclass)
                return True
        # Check if it's a subclass of a subclass (recursive)
        for scls in cls.__subclasses__():
            if issubclass(subclass, scls):
                cls._abc_cache.add(subclass)
                return True
        # No dice; update negative cache
        cls._abc_negative_cache.add(subclass)
        return False


def _hasattr(C, attr):
    try:
        return any(attr in B.__dict__ for B in C.__mro__)
    except AttributeError:
        # Old-style class
        return hasattr(C, attr)


class Sized:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __len__(self):
        return 0

    @classmethod
    def __subclasshook__(cls, C):
        if cls is Sized:
            if _hasattr(C, "__len__"):
                return True
        return NotImplemented


class Container:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __contains__(self, x):
        return False

    @classmethod
    def __subclasshook__(cls, C):
        if cls is Container:
            if _hasattr(C, "__contains__"):
                return True
        return NotImplemented


class Iterable:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __iter__(self):
        while False:
            yield None

    @classmethod
    def __subclasshook__(cls, C):
        if cls is Iterable:
            if _hasattr(C, "__iter__"):
                return True
        return NotImplemented

Iterable.register(str)


class Set(Sized, Iterable, Container):
    """A set is a finite, iterable container.

    This class provides concrete generic implementations of all
    methods except for __contains__, __iter__ and __len__.

    To override the comparisons (presumably for speed, as the
    semantics are fixed), all you have to do is redefine __le__ and
    then the other operations will automatically follow suit.
    """

    def __le__(self, other):
        if not isinstance(other, Set):
            return NotImplemented
        if len(self) > len(other):
            return False
        for elem in self:
            if elem not in other:
                return False
        return True

    def __lt__(self, other):
        if not isinstance(other, Set):
            return NotImplemented
        return len(self) < len(other) and self.__le__(other)

    def __gt__(self, other):
        if not isinstance(other, Set):
            return NotImplemented
        return other < self

    def __ge__(self, other):
        if not isinstance(other, Set):
            return NotImplemented
        return other <= self

    def __eq__(self, other):
        if not isinstance(other, Set):
            return NotImplemented
        return len(self) == len(other) and self.__le__(other)

    def __ne__(self, other):
        return not (self == other)

    @classmethod
    def _from_iterable(cls, it):
        '''Construct an instance of the class from any iterable input.

        Must override this method if the class constructor signature
        does not accept an iterable for an input.
        '''
        return cls(it)

    def __and__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        return self._from_iterable(value for value in other if value in self)

    def isdisjoint(self, other):
        for value in other:
            if value in self:
                return False
        return True

    def __or__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        chain = (e for s in (self, other) for e in s)
        return self._from_iterable(chain)

    def __sub__(self, other):
        if not isinstance(other, Set):
            if not isinstance(other, Iterable):
                return NotImplemented
            other = self._from_iterable(other)
        return self._from_iterable(value for value in self
                                   if value not in other)

    def __xor__(self, other):
        if not isinstance(other, Set):
            if not isinstance(other, Iterable):
                return NotImplemented
            other = self._from_iterable(other)
        return (self - other) | (other - self)

    # Sets are not hashable by default, but subclasses can change this
    __hash__ = None

    def _hash(self):
        """Compute the hash value of a set.

        Note that we don't define __hash__: not all sets are hashable.
        But if you define a hashable set type, its __hash__ should
        call this function.

        This must be compatible __eq__.

        All sets ought to compare equal if they contain the same
        elements, regardless of how they are implemented, and
        regardless of the order of the elements; so there's not much
        freedom for __eq__ or __hash__.  We match the algorithm used
        by the built-in frozenset type.
        """
        MAX = sys.maxint
        MASK = 2 * MAX + 1
        n = len(self)
        h = 1927868237 * (n + 1)
        h &= MASK
        for x in self:
            hx = hash(x)
            h ^= (hx ^ (hx << 16) ^ 89869747) * 3644798167
            h &= MASK
        h = h * 69069 + 907133923
        h &= MASK
        if h > MAX:
            h -= MASK + 1
        if h == -1:
            h = 590923713
        return h

Set.register(frozenset)


class MutableSet(Set):

    @abstractmethod
    def add(self, value):
        """Add an element."""
        raise NotImplementedError

    @abstractmethod
    def discard(self, value):
        """Remove an element.  Do not raise an exception if absent."""
        raise NotImplementedError

    def remove(self, value):
        """Remove an element. If not a member, raise a KeyError."""
        if value not in self:
            raise KeyError(value)
        self.discard(value)

    def pop(self):
        """Return the popped value.  Raise KeyError if empty."""
        it = iter(self)
        try:
            value = it.next()
        except StopIteration:
            raise KeyError
        self.discard(value)
        return value

    def clear(self):
        """This is slow (creates N new iterators!) but effective."""
        try:
            while True:
                self.pop()
        except KeyError:
            pass

    def __ior__(self, it):
        for value in it:
            self.add(value)
        return self

    def __iand__(self, it):
        for value in (self - it):
            self.discard(value)
        return self

    def __ixor__(self, it):
        if not isinstance(it, Set):
            it = self._from_iterable(it)
        for value in it:
            if value in self:
                self.discard(value)
            else:
                self.add(value)
        return self

    def __isub__(self, it):
        for value in it:
            self.discard(value)
        return self

MutableSet.register(set)


class OrderedSet(MutableSet):

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def __getitem__(self, key):
        return list(self)[key]

    def add(self, key):
        if key not in self.map:
            end = self.end
            curr = end[PREV]
            curr[NEXT] = end[PREV] = self.map[key] = [key, curr, end]

    def discard(self, key):
        if key in self.map:
            key, prev, next = self.map.pop(key)
            prev[NEXT] = next
            next[PREV] = prev

    def __iter__(self):
        end = self.end
        curr = end[NEXT]
        while curr is not end:
            yield curr[KEY]
            curr = curr[NEXT]

    def __reversed__(self):
        end = self.end
        curr = end[PREV]
        while curr is not end:
            yield curr[KEY]
            curr = curr[PREV]

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = reversed(self).next() if last else iter(self).next()
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)

    def __del__(self):
        self.clear()                    # remove circular references

if __name__ == '__main__':
    print(OrderedSet('abracadaba'))
    print(OrderedSet('simsalabim'))
