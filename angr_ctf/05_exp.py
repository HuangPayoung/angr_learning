import angr


def main():
    project = angr.Project('./05_angr_symbolic_memory')
    start_addr = 0x08048601
    start_state = project.factory.blank_state(addr = start_addr)
    simulation = project.factory.simgr(start_state)

    password1 = start_state.solver.BVS("password1", 64)
    password2 = start_state.solver.BVS("password2", 64)
    password3 = start_state.solver.BVS("password3", 64)
    password4 = start_state.solver.BVS("password4", 64)

    start_state.regs.ebp = start_state.regs.esp
    start_state.regs.esp -= 0x18
    start_state.memory.store(0x0A1BA1C0, password1)
    start_state.memory.store(0x0A1BA1C8, password2)
    start_state.memory.store(0x0A1BA1D0, password3)
    start_state.memory.store(0x0A1BA1D8, password4)

    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
        input2 = solution_state.solver.eval(password2, cast_to=bytes).decode()
        input3 = solution_state.solver.eval(password3, cast_to=bytes).decode()
        input4 = solution_state.solver.eval(password4, cast_to=bytes).decode()
        print('Success: {} {} {} {}'.format(input1, input2, input3, input4))


if __name__ == '__main__':
	main() 
