import angr
import claripy


def main():
    project = angr.Project('./09_angr_hooks')
    check_fun, check_skip_size = 0x080486B3, 5
    start_state = project.factory.entry_state()
    simulation = project.factory.simgr(start_state)


    @project.hook(check_fun, length=check_skip_size)
    def check_hook(state):
        desire_string = 'XYMKBKUHNIQYNQXE'
        buffer_addr, buffer_size = 0x0804A054, 0x10
        input_bvs = state.memory.load(buffer_addr, buffer_size)
        state.regs.eax = claripy.If(
            input_bvs == desire_string,
            state.solver.BVV(1, 32),
            state.solver.BVV(0, 32)
        )
        ''' useless
        if input_bvs == desire_string:
            state.regs.eax = state.solver.BVV(1, 32)
        else:
            state.regs.eax = state.solver.BVV(0, 32)
        '''


    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input = solution_state.posix.dumps(0).decode()
        print('Success: {}'.format(input))
    else:
        raise Exception('Solution not found!')


if __name__ == '__main__':
	main() 
