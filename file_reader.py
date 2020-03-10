# -*- coding=utf8 -*-
import struct


class FileReader(object):
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

    def __init__(self, file_or_filename, block_size=2048):
        if isinstance(file_or_filename, str):
            file_or_filename = open(file_or_filename, 'rb')
        self.f = file_or_filename
        self.block_size = block_size if block_size > 0 else 2048
        self.cache = self.f.read(self.block_size)
        self.cache_cursor = 0
        self.file_cursor = 0
        self.section_list = None
        self.image_base = 0

    def read(self, n):
        if n < len(self.cache) - self.cache_cursor:
            ret = self.cache[self.cache_cursor:self.cache_cursor + n]
            self.cache_cursor += n
            self.file_cursor += n
            return ret
        else:
            ret = self.cache[self.cache_cursor:]
            old_size = len(ret)
            ret += self.f.read(n - len(ret))
            self.file_cursor += old_size - len(ret)
            self.cache_cursor = 0
            self.cache = self.f.read(self.block_size)
            return ret

    def unpack(self, type_str, size=None):
        if size is None:
            size = self._auto_calc_size(type_str)
        ret = struct.unpack(type_str, self.read(size))
        return ret if len(ret) != 1 else ret[0]

    def _auto_calc_size(self, type_str):
        return sum(self.type_to_size[char] for char in type_str)

    def seek(self, pos):
        self.f.seek(pos)
        self.file_cursor = pos
        self.cache_cursor = 0
        self.cache = self.f.read(self.block_size)

    def set_image_base(self, image_base):
        self.image_base = image_base

    def set_setion_list(self, section_list):
        self.section_list = section_list



