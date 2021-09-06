import angr


def main():
    project = angr.Project('./04_angr_symbolic_stack')
    start_addr = 0x08048697
    start_state = project.factory.blank_state(addr = start_addr)
    simulation = project.factory.simgr(start_state)

    password1 = start_state.solver.BVS("password1", 32)
    password2 = start_state.solver.BVS("password2", 32)

    start_state.regs.ebp = start_state.regs.esp
    start_state.regs.esp -= 8
    start_state.stack_push(password1)
    start_state.stack_push(password2)
    start_state.regs.esp -= 8

    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input1 = solution_state.solver.eval(password1)
        input2 = solution_state.solver.eval(password2)
        print('Success: {} {}'.format(input1, input2))


if __name__ == '__main__':
	main() 
