# -*- coding=utf8 -*-
import struct
import io


class TypeMeta(type):
    def __call__(cls, *args, **kwargs):
        new_instance = type.__call__(cls, *args, **kwargs)
        new_instance.id = BaseType.instance_count
        BaseType.instance_count += 1
        attr_list = []
        for key in dir(cls):
            value = getattr(cls, key, None)
            if isinstance(value, BaseType):
                value.name = key
                value.parent = new_instance
                setattr(new_instance, key, value.copy())
                attr_list.append(key)
        attr_list.sort(key=lambda x: getattr(cls, x).id)
        cls.attr_list = attr_list
        return new_instance

    def __new__(mcs, *args, **kwargs):
        return type.__new__(mcs, *args, **kwargs)


class BaseType(object):
    __metaclass__ = TypeMeta
    TYPE = None
    instance_count = 0
    type_to_size = {
        'c': 1,
        'b': 1,
        'B': 1,
        '?': 1,
        's': 1,
        'h': 2,
        'H': 2,
        'i': 4,
        'I': 4,
        'l': 4,
        'L': 4,
        'f': 4,
        'q': 8,
        'Q': 8,
        'd': 8,
        # 'p': '?',
        # 'P': '?',
    }

    def __init__(self, num=1):
        self._num = num
        self._value = None
        self.list = []

    def parse(self, stream):
        # 接收btye类型，截取正好的长度
        if isinstance(stream, bytes):
            stream = io.BytesIO(stream)
        self._parse(stream)

    def _parse(self, stream):
        if not self.is_complex_type:
            self._value = self.unpack(stream.read(self.size))
        elif not self.is_list_type:
            for attr_name in self.attr_list:
                attr = getattr(self, attr_name)
                attr.parse(stream)
        else:
            self.list = [self.__class__(1) for _ in range(self.num)]
            for each_self in self.list:
                each_self.parse(stream)

    def unpack(self, value):
        return struct.unpack(self.TYPE * self.num, value)

    def copy(self):
        ret = self.__class__(self._num)
        ret.name = self.name
        ret.parent = self.parent
        return ret

    @property
    def num(self):
        if callable(self._num):
            return self._num(self.parent)
        return self._num

    @property
    def value(self):
        if self._value and len(self._value) == 1:
            return self._value[0]
        return self._value

    @property
    def is_complex_type(self):
        return bool(self.attr_list)

    @property
    def is_list_type(self):
        return self.num > 1

    @property
    def size(self):
        if not self.is_complex_type:
            return self.type_to_size[self.TYPE] * self.num
        else:
            ret = 0
            for attr in self.attr_list:
                ret += getattr(self, attr).size
            return ret * self.num

    @property
    def default(self):
        if self.is_complex_type:
            return self
        return None

    @property
    def attrs(self):
        return [getattr(self, attr_name) for attr_name in self.attr_list]

    def __repr__(self):
        return self.to_repr()

    def __getitem__(self, item):
        return self.list[item]

    def to_repr(self, level=1):
        member_indent = '\t' * level
        last_indent = '\t' * (level - 1)
        sep = ', \n' + member_indent
        if not self.is_complex_type:
            value = '({}{})'.format(self.__class__.__name__.capitalize(), self.num if self.num > 1 else '') + repr(self.value)
        elif not self.is_list_type:
            value = sep.join(['{0}={1}'.format(attr.name, attr.to_repr(level+1)) for attr in self.attrs])
            value = '{0}(\n{2}{1}\n{3})'.format(self.__class__.__name__, value, member_indent, last_indent)
        else:
            value = sep.join([attr.to_repr(level + 1) for attr in self.list])
            value = '[\n{1}{0}\n{2}]'.format(value, member_indent, last_indent)
        return value


class WORD(BaseType):
    TYPE = 'H'  # unsigned short


class DWORD(BaseType):
    TYPE = 'I'  # unsigned int


class BYTE(BaseType):
    TYPE = 'c'  # char

    @property
    def value(self):
        return ''.join(self._value)


class PADDING(BYTE):
    pass


class SEEK(BaseType):
    def _parse(self, stream):
        stream.seek(self.num)


class STR(DWORD):
    def _parse(self, stream):
        super(STR, self)._parse(stream)
        old_pos = stream.file_cursor
        self._resolve(stream)
        stream.seek(old_pos)

    def _resolve(self, f):
        ret = []
        for ptr in self._value:
            string = ''
            f.seek(self.parent.rva_to_addr(ptr))
            while True:
                char = f.read(1)
                if ord(char) == 0:
                    break
                string += char
            ret.append(string)
        self._value = ret


class LONG(BaseType):
    TYPE = 'q'  # signed long long

