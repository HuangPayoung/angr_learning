import angr

'''
def main():
    project = angr.Project('./03_angr_symbolic_registers')
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    for solution_state in simulation.found:
	    solution = solution_state.posix.dumps(0)
    print('Success: ' + solution.decode())	
'''

def main():
    project = angr.Project('./03_angr_symbolic_registers')
    start_addr = 0x08048980
    start_state = project.factory.blank_state(addr = start_addr)
    simulation = project.factory.simgr(start_state)

    password1 = start_state.solver.BVS("password1", 32)
    password2 = start_state.solver.BVS("password2", 32)
    password3 = start_state.solver.BVS("password3", 32)
    start_state.regs.eax = password1
    start_state.regs.ebx = password2
    start_state.regs.edx = password3


    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input1 = solution_state.solver.eval(password1)
        input2 = solution_state.solver.eval(password2)
        input3 = solution_state.solver.eval(password3)
        print('Success: {:x} {:x} {:x}'.format(input1, input2, input3))


if __name__ == '__main__':
	main() 
