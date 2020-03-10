# -*- coding=utf8 -*-
from file_reader import FileReader

if __name__ == '__main__':
    file_name = 'Coroutine_x64h.dll'
    f = FileReader(file_name, 1024)
    # dos header
    print f.unpack('h' * 14)
    print f.unpack('h' * 4)
    print f.unpack('h' * 2)
    print f.unpack('h' * 10)    #
    ifanew = f.unpack('I')         # ifanew, offset to pe header
    print 'ifanew', ifanew

    # pe header
    f.seek(ifanew)
    print f.unpack('I')
    print f.unpack('hhIIIhh')

