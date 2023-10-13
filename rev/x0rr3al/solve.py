import angr

project = angr.Project("./x0rr3al", main_opts={'base_addr': 0}, auto_load_libs=False)

initial_state = project.factory.entry_state()
print(initial_state)

sm =project.factory.simgr(initial_state)

good_addr = 0x01b62

avoid_addrs = [0x16ad, 0x156a]
sm.explore(find=good_addr, avoid=avoid_addrs)
print(sm.found[0].posix.dumps(0))

# vsctf{w34k_4nt1_d3bugg3rs_4r3_n0_m4tch_f0r_th3_31337}
