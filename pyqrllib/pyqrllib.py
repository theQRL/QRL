# This file was automatically generated by SWIG (http://www.swig.org).
# Version 3.0.8
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.





from sys import version_info
if version_info >= (2, 6, 0):
    def swig_import_helper():
        from os.path import dirname
        import imp
        fp = None
        try:
            fp, pathname, description = imp.find_module('_pyqrllib', [dirname(__file__)])
        except ImportError:
            import _pyqrllib
            return _pyqrllib
        if fp is not None:
            try:
                _mod = imp.load_module('_pyqrllib', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _pyqrllib = swig_import_helper()
    del swig_import_helper
else:
    import _pyqrllib
del version_info
try:
    _swig_property = property
except NameError:
    pass  # Python < 2.2 doesn't have 'property'.


def _swig_setattr_nondynamic(self, class_type, name, value, static=1):
    if (name == "thisown"):
        return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'SwigPyObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name, None)
    if method:
        return method(self, value)
    if (not static):
        if _newclass:
            object.__setattr__(self, name, value)
        else:
            self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)


def _swig_setattr(self, class_type, name, value):
    return _swig_setattr_nondynamic(self, class_type, name, value, 0)


def _swig_getattr_nondynamic(self, class_type, name, static=1):
    if (name == "thisown"):
        return self.this.own()
    method = class_type.__swig_getmethods__.get(name, None)
    if method:
        return method(self)
    if (not static):
        return object.__getattr__(self, name)
    else:
        raise AttributeError(name)

def _swig_getattr(self, class_type, name):
    return _swig_getattr_nondynamic(self, class_type, name, 0)


def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

try:
    _object = object
    _newclass = 1
except AttributeError:
    class _object:
        pass
    _newclass = 0



def cdata(ptr, nelements=1):
    return _pyqrllib.cdata(ptr, nelements)
cdata = _pyqrllib.cdata

def memmove(data, indata):
    return _pyqrllib.memmove(data, indata)
memmove = _pyqrllib.memmove
class SwigPyIterator(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, SwigPyIterator, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, SwigPyIterator, name)

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    __swig_destroy__ = _pyqrllib.delete_SwigPyIterator
    __del__ = lambda self: None

    def value(self):
        return _pyqrllib.SwigPyIterator_value(self)

    def incr(self, n=1):
        return _pyqrllib.SwigPyIterator_incr(self, n)

    def decr(self, n=1):
        return _pyqrllib.SwigPyIterator_decr(self, n)

    def distance(self, x):
        return _pyqrllib.SwigPyIterator_distance(self, x)

    def equal(self, x):
        return _pyqrllib.SwigPyIterator_equal(self, x)

    def copy(self):
        return _pyqrllib.SwigPyIterator_copy(self)

    def next(self):
        return _pyqrllib.SwigPyIterator_next(self)

    def __next__(self):
        return _pyqrllib.SwigPyIterator___next__(self)

    def previous(self):
        return _pyqrllib.SwigPyIterator_previous(self)

    def advance(self, n):
        return _pyqrllib.SwigPyIterator_advance(self, n)

    def __eq__(self, x):
        return _pyqrllib.SwigPyIterator___eq__(self, x)

    def __ne__(self, x):
        return _pyqrllib.SwigPyIterator___ne__(self, x)

    def __iadd__(self, n):
        return _pyqrllib.SwigPyIterator___iadd__(self, n)

    def __isub__(self, n):
        return _pyqrllib.SwigPyIterator___isub__(self, n)

    def __add__(self, n):
        return _pyqrllib.SwigPyIterator___add__(self, n)

    def __sub__(self, *args):
        return _pyqrllib.SwigPyIterator___sub__(self, *args)
    def __iter__(self):
        return self
SwigPyIterator_swigregister = _pyqrllib.SwigPyIterator_swigregister
SwigPyIterator_swigregister(SwigPyIterator)

class ucharCArray(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ucharCArray, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ucharCArray, name)
    __repr__ = _swig_repr

    def __init__(self, nelements):
        this = _pyqrllib.new_ucharCArray(nelements)
        try:
            self.this.append(this)
        except Exception:
            self.this = this
    __swig_destroy__ = _pyqrllib.delete_ucharCArray
    __del__ = lambda self: None

    def __getitem__(self, index):
        return _pyqrllib.ucharCArray___getitem__(self, index)

    def __setitem__(self, index, value):
        return _pyqrllib.ucharCArray___setitem__(self, index, value)

    def cast(self):
        return _pyqrllib.ucharCArray_cast(self)
    __swig_getmethods__["frompointer"] = lambda x: _pyqrllib.ucharCArray_frompointer
    if _newclass:
        frompointer = staticmethod(_pyqrllib.ucharCArray_frompointer)
ucharCArray_swigregister = _pyqrllib.ucharCArray_swigregister
ucharCArray_swigregister(ucharCArray)

def ucharCArray_frompointer(t):
    return _pyqrllib.ucharCArray_frompointer(t)
ucharCArray_frompointer = _pyqrllib.ucharCArray_frompointer

class uintCArray(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, uintCArray, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, uintCArray, name)
    __repr__ = _swig_repr

    def __init__(self, nelements):
        this = _pyqrllib.new_uintCArray(nelements)
        try:
            self.this.append(this)
        except Exception:
            self.this = this
    __swig_destroy__ = _pyqrllib.delete_uintCArray
    __del__ = lambda self: None

    def __getitem__(self, index):
        return _pyqrllib.uintCArray___getitem__(self, index)

    def __setitem__(self, index, value):
        return _pyqrllib.uintCArray___setitem__(self, index, value)

    def cast(self):
        return _pyqrllib.uintCArray_cast(self)
    __swig_getmethods__["frompointer"] = lambda x: _pyqrllib.uintCArray_frompointer
    if _newclass:
        frompointer = staticmethod(_pyqrllib.uintCArray_frompointer)
uintCArray_swigregister = _pyqrllib.uintCArray_swigregister
uintCArray_swigregister(uintCArray)

def uintCArray_frompointer(t):
    return _pyqrllib.uintCArray_frompointer(t)
uintCArray_frompointer = _pyqrllib.uintCArray_frompointer

class uint32CArray(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, uint32CArray, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, uint32CArray, name)
    __repr__ = _swig_repr

    def __init__(self, nelements):
        this = _pyqrllib.new_uint32CArray(nelements)
        try:
            self.this.append(this)
        except Exception:
            self.this = this
    __swig_destroy__ = _pyqrllib.delete_uint32CArray
    __del__ = lambda self: None

    def __getitem__(self, index):
        return _pyqrllib.uint32CArray___getitem__(self, index)

    def __setitem__(self, index, value):
        return _pyqrllib.uint32CArray___setitem__(self, index, value)

    def cast(self):
        return _pyqrllib.uint32CArray_cast(self)
    __swig_getmethods__["frompointer"] = lambda x: _pyqrllib.uint32CArray_frompointer
    if _newclass:
        frompointer = staticmethod(_pyqrllib.uint32CArray_frompointer)
uint32CArray_swigregister = _pyqrllib.uint32CArray_swigregister
uint32CArray_swigregister(uint32CArray)

def uint32CArray_frompointer(t):
    return _pyqrllib.uint32CArray_frompointer(t)
uint32CArray_frompointer = _pyqrllib.uint32CArray_frompointer

class intVector(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, intVector, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, intVector, name)
    __repr__ = _swig_repr

    def iterator(self):
        return _pyqrllib.intVector_iterator(self)
    def __iter__(self):
        return self.iterator()

    def __nonzero__(self):
        return _pyqrllib.intVector___nonzero__(self)

    def __bool__(self):
        return _pyqrllib.intVector___bool__(self)

    def __len__(self):
        return _pyqrllib.intVector___len__(self)

    def __getslice__(self, i, j):
        return _pyqrllib.intVector___getslice__(self, i, j)

    def __setslice__(self, *args):
        return _pyqrllib.intVector___setslice__(self, *args)

    def __delslice__(self, i, j):
        return _pyqrllib.intVector___delslice__(self, i, j)

    def __delitem__(self, *args):
        return _pyqrllib.intVector___delitem__(self, *args)

    def __getitem__(self, *args):
        return _pyqrllib.intVector___getitem__(self, *args)

    def __setitem__(self, *args):
        return _pyqrllib.intVector___setitem__(self, *args)

    def pop(self):
        return _pyqrllib.intVector_pop(self)

    def append(self, x):
        return _pyqrllib.intVector_append(self, x)

    def empty(self):
        return _pyqrllib.intVector_empty(self)

    def size(self):
        return _pyqrllib.intVector_size(self)

    def swap(self, v):
        return _pyqrllib.intVector_swap(self, v)

    def begin(self):
        return _pyqrllib.intVector_begin(self)

    def end(self):
        return _pyqrllib.intVector_end(self)

    def rbegin(self):
        return _pyqrllib.intVector_rbegin(self)

    def rend(self):
        return _pyqrllib.intVector_rend(self)

    def clear(self):
        return _pyqrllib.intVector_clear(self)

    def get_allocator(self):
        return _pyqrllib.intVector_get_allocator(self)

    def pop_back(self):
        return _pyqrllib.intVector_pop_back(self)

    def erase(self, *args):
        return _pyqrllib.intVector_erase(self, *args)

    def __init__(self, *args):
        this = _pyqrllib.new_intVector(*args)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def push_back(self, x):
        return _pyqrllib.intVector_push_back(self, x)

    def front(self):
        return _pyqrllib.intVector_front(self)

    def back(self):
        return _pyqrllib.intVector_back(self)

    def assign(self, n, x):
        return _pyqrllib.intVector_assign(self, n, x)

    def resize(self, *args):
        return _pyqrllib.intVector_resize(self, *args)

    def insert(self, *args):
        return _pyqrllib.intVector_insert(self, *args)

    def reserve(self, n):
        return _pyqrllib.intVector_reserve(self, n)

    def capacity(self):
        return _pyqrllib.intVector_capacity(self)
    __swig_destroy__ = _pyqrllib.delete_intVector
    __del__ = lambda self: None
intVector_swigregister = _pyqrllib.intVector_swigregister
intVector_swigregister(intVector)

class uintVector(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, uintVector, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, uintVector, name)
    __repr__ = _swig_repr

    def iterator(self):
        return _pyqrllib.uintVector_iterator(self)
    def __iter__(self):
        return self.iterator()

    def __nonzero__(self):
        return _pyqrllib.uintVector___nonzero__(self)

    def __bool__(self):
        return _pyqrllib.uintVector___bool__(self)

    def __len__(self):
        return _pyqrllib.uintVector___len__(self)

    def __getslice__(self, i, j):
        return _pyqrllib.uintVector___getslice__(self, i, j)

    def __setslice__(self, *args):
        return _pyqrllib.uintVector___setslice__(self, *args)

    def __delslice__(self, i, j):
        return _pyqrllib.uintVector___delslice__(self, i, j)

    def __delitem__(self, *args):
        return _pyqrllib.uintVector___delitem__(self, *args)

    def __getitem__(self, *args):
        return _pyqrllib.uintVector___getitem__(self, *args)

    def __setitem__(self, *args):
        return _pyqrllib.uintVector___setitem__(self, *args)

    def pop(self):
        return _pyqrllib.uintVector_pop(self)

    def append(self, x):
        return _pyqrllib.uintVector_append(self, x)

    def empty(self):
        return _pyqrllib.uintVector_empty(self)

    def size(self):
        return _pyqrllib.uintVector_size(self)

    def swap(self, v):
        return _pyqrllib.uintVector_swap(self, v)

    def begin(self):
        return _pyqrllib.uintVector_begin(self)

    def end(self):
        return _pyqrllib.uintVector_end(self)

    def rbegin(self):
        return _pyqrllib.uintVector_rbegin(self)

    def rend(self):
        return _pyqrllib.uintVector_rend(self)

    def clear(self):
        return _pyqrllib.uintVector_clear(self)

    def get_allocator(self):
        return _pyqrllib.uintVector_get_allocator(self)

    def pop_back(self):
        return _pyqrllib.uintVector_pop_back(self)

    def erase(self, *args):
        return _pyqrllib.uintVector_erase(self, *args)

    def __init__(self, *args):
        this = _pyqrllib.new_uintVector(*args)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def push_back(self, x):
        return _pyqrllib.uintVector_push_back(self, x)

    def front(self):
        return _pyqrllib.uintVector_front(self)

    def back(self):
        return _pyqrllib.uintVector_back(self)

    def assign(self, n, x):
        return _pyqrllib.uintVector_assign(self, n, x)

    def resize(self, *args):
        return _pyqrllib.uintVector_resize(self, *args)

    def insert(self, *args):
        return _pyqrllib.uintVector_insert(self, *args)

    def reserve(self, n):
        return _pyqrllib.uintVector_reserve(self, n)

    def capacity(self):
        return _pyqrllib.uintVector_capacity(self)
    __swig_destroy__ = _pyqrllib.delete_uintVector
    __del__ = lambda self: None
uintVector_swigregister = _pyqrllib.uintVector_swigregister
uintVector_swigregister(uintVector)

class ucharVector(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ucharVector, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ucharVector, name)
    __repr__ = _swig_repr

    def iterator(self):
        return _pyqrllib.ucharVector_iterator(self)
    def __iter__(self):
        return self.iterator()

    def __nonzero__(self):
        return _pyqrllib.ucharVector___nonzero__(self)

    def __bool__(self):
        return _pyqrllib.ucharVector___bool__(self)

    def __len__(self):
        return _pyqrllib.ucharVector___len__(self)

    def __getslice__(self, i, j):
        return _pyqrllib.ucharVector___getslice__(self, i, j)

    def __setslice__(self, *args):
        return _pyqrllib.ucharVector___setslice__(self, *args)

    def __delslice__(self, i, j):
        return _pyqrllib.ucharVector___delslice__(self, i, j)

    def __delitem__(self, *args):
        return _pyqrllib.ucharVector___delitem__(self, *args)

    def __getitem__(self, *args):
        return _pyqrllib.ucharVector___getitem__(self, *args)

    def __setitem__(self, *args):
        return _pyqrllib.ucharVector___setitem__(self, *args)

    def pop(self):
        return _pyqrllib.ucharVector_pop(self)

    def append(self, x):
        return _pyqrllib.ucharVector_append(self, x)

    def empty(self):
        return _pyqrllib.ucharVector_empty(self)

    def size(self):
        return _pyqrllib.ucharVector_size(self)

    def swap(self, v):
        return _pyqrllib.ucharVector_swap(self, v)

    def begin(self):
        return _pyqrllib.ucharVector_begin(self)

    def end(self):
        return _pyqrllib.ucharVector_end(self)

    def rbegin(self):
        return _pyqrllib.ucharVector_rbegin(self)

    def rend(self):
        return _pyqrllib.ucharVector_rend(self)

    def clear(self):
        return _pyqrllib.ucharVector_clear(self)

    def get_allocator(self):
        return _pyqrllib.ucharVector_get_allocator(self)

    def pop_back(self):
        return _pyqrllib.ucharVector_pop_back(self)

    def erase(self, *args):
        return _pyqrllib.ucharVector_erase(self, *args)

    def __init__(self, *args):
        this = _pyqrllib.new_ucharVector(*args)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def push_back(self, x):
        return _pyqrllib.ucharVector_push_back(self, x)

    def front(self):
        return _pyqrllib.ucharVector_front(self)

    def back(self):
        return _pyqrllib.ucharVector_back(self)

    def assign(self, n, x):
        return _pyqrllib.ucharVector_assign(self, n, x)

    def resize(self, *args):
        return _pyqrllib.ucharVector_resize(self, *args)

    def insert(self, *args):
        return _pyqrllib.ucharVector_insert(self, *args)

    def reserve(self, n):
        return _pyqrllib.ucharVector_reserve(self, n)

    def capacity(self):
        return _pyqrllib.ucharVector_capacity(self)
    __swig_destroy__ = _pyqrllib.delete_ucharVector
    __del__ = lambda self: None
ucharVector_swigregister = _pyqrllib.ucharVector_swigregister
ucharVector_swigregister(ucharVector)

class charVector(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, charVector, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, charVector, name)
    __repr__ = _swig_repr

    def iterator(self):
        return _pyqrllib.charVector_iterator(self)
    def __iter__(self):
        return self.iterator()

    def __nonzero__(self):
        return _pyqrllib.charVector___nonzero__(self)

    def __bool__(self):
        return _pyqrllib.charVector___bool__(self)

    def __len__(self):
        return _pyqrllib.charVector___len__(self)

    def __getslice__(self, i, j):
        return _pyqrllib.charVector___getslice__(self, i, j)

    def __setslice__(self, *args):
        return _pyqrllib.charVector___setslice__(self, *args)

    def __delslice__(self, i, j):
        return _pyqrllib.charVector___delslice__(self, i, j)

    def __delitem__(self, *args):
        return _pyqrllib.charVector___delitem__(self, *args)

    def __getitem__(self, *args):
        return _pyqrllib.charVector___getitem__(self, *args)

    def __setitem__(self, *args):
        return _pyqrllib.charVector___setitem__(self, *args)

    def pop(self):
        return _pyqrllib.charVector_pop(self)

    def append(self, x):
        return _pyqrllib.charVector_append(self, x)

    def empty(self):
        return _pyqrllib.charVector_empty(self)

    def size(self):
        return _pyqrllib.charVector_size(self)

    def swap(self, v):
        return _pyqrllib.charVector_swap(self, v)

    def begin(self):
        return _pyqrllib.charVector_begin(self)

    def end(self):
        return _pyqrllib.charVector_end(self)

    def rbegin(self):
        return _pyqrllib.charVector_rbegin(self)

    def rend(self):
        return _pyqrllib.charVector_rend(self)

    def clear(self):
        return _pyqrllib.charVector_clear(self)

    def get_allocator(self):
        return _pyqrllib.charVector_get_allocator(self)

    def pop_back(self):
        return _pyqrllib.charVector_pop_back(self)

    def erase(self, *args):
        return _pyqrllib.charVector_erase(self, *args)

    def __init__(self, *args):
        this = _pyqrllib.new_charVector(*args)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def push_back(self, x):
        return _pyqrllib.charVector_push_back(self, x)

    def front(self):
        return _pyqrllib.charVector_front(self)

    def back(self):
        return _pyqrllib.charVector_back(self)

    def assign(self, n, x):
        return _pyqrllib.charVector_assign(self, n, x)

    def resize(self, *args):
        return _pyqrllib.charVector_resize(self, *args)

    def insert(self, *args):
        return _pyqrllib.charVector_insert(self, *args)

    def reserve(self, n):
        return _pyqrllib.charVector_reserve(self, n)

    def capacity(self):
        return _pyqrllib.charVector_capacity(self)
    __swig_destroy__ = _pyqrllib.delete_charVector
    __del__ = lambda self: None
charVector_swigregister = _pyqrllib.charVector_swigregister
charVector_swigregister(charVector)

class doubleVector(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, doubleVector, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, doubleVector, name)
    __repr__ = _swig_repr

    def iterator(self):
        return _pyqrllib.doubleVector_iterator(self)
    def __iter__(self):
        return self.iterator()

    def __nonzero__(self):
        return _pyqrllib.doubleVector___nonzero__(self)

    def __bool__(self):
        return _pyqrllib.doubleVector___bool__(self)

    def __len__(self):
        return _pyqrllib.doubleVector___len__(self)

    def __getslice__(self, i, j):
        return _pyqrllib.doubleVector___getslice__(self, i, j)

    def __setslice__(self, *args):
        return _pyqrllib.doubleVector___setslice__(self, *args)

    def __delslice__(self, i, j):
        return _pyqrllib.doubleVector___delslice__(self, i, j)

    def __delitem__(self, *args):
        return _pyqrllib.doubleVector___delitem__(self, *args)

    def __getitem__(self, *args):
        return _pyqrllib.doubleVector___getitem__(self, *args)

    def __setitem__(self, *args):
        return _pyqrllib.doubleVector___setitem__(self, *args)

    def pop(self):
        return _pyqrllib.doubleVector_pop(self)

    def append(self, x):
        return _pyqrllib.doubleVector_append(self, x)

    def empty(self):
        return _pyqrllib.doubleVector_empty(self)

    def size(self):
        return _pyqrllib.doubleVector_size(self)

    def swap(self, v):
        return _pyqrllib.doubleVector_swap(self, v)

    def begin(self):
        return _pyqrllib.doubleVector_begin(self)

    def end(self):
        return _pyqrllib.doubleVector_end(self)

    def rbegin(self):
        return _pyqrllib.doubleVector_rbegin(self)

    def rend(self):
        return _pyqrllib.doubleVector_rend(self)

    def clear(self):
        return _pyqrllib.doubleVector_clear(self)

    def get_allocator(self):
        return _pyqrllib.doubleVector_get_allocator(self)

    def pop_back(self):
        return _pyqrllib.doubleVector_pop_back(self)

    def erase(self, *args):
        return _pyqrllib.doubleVector_erase(self, *args)

    def __init__(self, *args):
        this = _pyqrllib.new_doubleVector(*args)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def push_back(self, x):
        return _pyqrllib.doubleVector_push_back(self, x)

    def front(self):
        return _pyqrllib.doubleVector_front(self)

    def back(self):
        return _pyqrllib.doubleVector_back(self)

    def assign(self, n, x):
        return _pyqrllib.doubleVector_assign(self, n, x)

    def resize(self, *args):
        return _pyqrllib.doubleVector_resize(self, *args)

    def insert(self, *args):
        return _pyqrllib.doubleVector_insert(self, *args)

    def reserve(self, n):
        return _pyqrllib.doubleVector_reserve(self, n)

    def capacity(self):
        return _pyqrllib.doubleVector_capacity(self)
    __swig_destroy__ = _pyqrllib.delete_doubleVector
    __del__ = lambda self: None
doubleVector_swigregister = _pyqrllib.doubleVector_swigregister
doubleVector_swigregister(doubleVector)

class Xmss(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, Xmss, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, Xmss, name)
    __repr__ = _swig_repr

    def __init__(self, seed, height):
        this = _pyqrllib.new_Xmss(seed, height)
        try:
            self.this.append(this)
        except Exception:
            self.this = this

    def sign(self, message):
        return _pyqrllib.Xmss_sign(self, message)

    def getHeight(self):
        return _pyqrllib.Xmss_getHeight(self)

    def getPK(self):
        return _pyqrllib.Xmss_getPK(self)

    def getSK(self):
        return _pyqrllib.Xmss_getSK(self)

    def getSeed(self):
        return _pyqrllib.Xmss_getSeed(self)

    def getRoot(self):
        return _pyqrllib.Xmss_getRoot(self)

    def getIndex(self):
        return _pyqrllib.Xmss_getIndex(self)

    def getPKSeed(self):
        return _pyqrllib.Xmss_getPKSeed(self)

    def getSKSeed(self):
        return _pyqrllib.Xmss_getSKSeed(self)

    def getSKPRF(self):
        return _pyqrllib.Xmss_getSKPRF(self)

    def getSignatureSize(self):
        return _pyqrllib.Xmss_getSignatureSize(self)

    def getSecretKeySize(self):
        return _pyqrllib.Xmss_getSecretKeySize(self)

    def getPublicKeySize(self):
        return _pyqrllib.Xmss_getPublicKeySize(self)
    __swig_destroy__ = _pyqrllib.delete_Xmss
    __del__ = lambda self: None
Xmss_swigregister = _pyqrllib.Xmss_swigregister
Xmss_swigregister(Xmss)


def verify(message, signature, pk, height):
    return _pyqrllib.verify(message, signature, pk, height)
verify = _pyqrllib.verify

_pyqrllib.ADDRESS_HASH_SIZE_swigconstant(_pyqrllib)
ADDRESS_HASH_SIZE = _pyqrllib.ADDRESS_HASH_SIZE

def vec2hexstr(*args):
    return _pyqrllib.vec2hexstr(*args)
vec2hexstr = _pyqrllib.vec2hexstr

def getAddress(*args):
    return _pyqrllib.getAddress(*args)
getAddress = _pyqrllib.getAddress

def tobin(s):
    return _pyqrllib.tobin(s)
tobin = _pyqrllib.tobin

def getRandomSeed(seed_size):
    return _pyqrllib.getRandomSeed(seed_size)
getRandomSeed = _pyqrllib.getRandomSeed

_pyqrllib.SHAKE128_RATE_swigconstant(_pyqrllib)
SHAKE128_RATE = _pyqrllib.SHAKE128_RATE

_pyqrllib.SHAKE256_RATE_swigconstant(_pyqrllib)
SHAKE256_RATE = _pyqrllib.SHAKE256_RATE

def shake128(out, outlen, arg3, inlen):
    return _pyqrllib.shake128(out, outlen, arg3, inlen)
shake128 = _pyqrllib.shake128

def shake256(out, outlen, arg3, inlen):
    return _pyqrllib.shake256(out, outlen, arg3, inlen)
shake256 = _pyqrllib.shake256

_pyqrllib.IS_LITTLE_ENDIAN_swigconstant(_pyqrllib)
IS_LITTLE_ENDIAN = _pyqrllib.IS_LITTLE_ENDIAN

def addr_to_byte(bytes, addr):
    return _pyqrllib.addr_to_byte(bytes, addr)
addr_to_byte = _pyqrllib.addr_to_byte

def prf(out, arg2, key, keylen):
    return _pyqrllib.prf(out, arg2, key, keylen)
prf = _pyqrllib.prf

def h_msg(out, arg2, inlen, key, keylen, n):
    return _pyqrllib.h_msg(out, arg2, inlen, key, keylen, n)
h_msg = _pyqrllib.h_msg

def hash_h(out, arg2, pub_seed, addr, n):
    return _pyqrllib.hash_h(out, arg2, pub_seed, addr, n)
hash_h = _pyqrllib.hash_h

def hash_f(out, arg2, pub_seed, addr, n):
    return _pyqrllib.hash_f(out, arg2, pub_seed, addr, n)
hash_f = _pyqrllib.hash_f
# This file is compatible with both classic and new-style classes.


