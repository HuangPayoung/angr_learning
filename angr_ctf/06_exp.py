import angr


def main():
    project = angr.Project('./06_angr_symbolic_dynamic_memory')
    start_addr, bss_buf = 0x08048699, 0x0804A080
    buffer0_addr, buffer1_addr = 0x0ABCC8A4, 0x0ABCC8AC
    start_state = project.factory.blank_state(addr = start_addr)
    simulation = project.factory.simgr(start_state)

    password1 = start_state.solver.BVS("password1", 64)
    password2 = start_state.solver.BVS("password2", 64)

    start_state.regs.ebp = start_state.regs.esp
    start_state.regs.esp -= 0x18
    start_state.memory.store(buffer0_addr, bss_buf, endness=project.arch.memory_endness)
    start_state.memory.store(buffer1_addr, bss_buf + 8, endness=project.arch.memory_endness)
    start_state.memory.store(bss_buf, password1)
    start_state.memory.store(bss_buf + 8, password2)

    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
        input2 = solution_state.solver.eval(password2, cast_to=bytes).decode()
        print('Success: {} {}'.format(input1, input2))


if __name__ == '__main__':
	main() 
