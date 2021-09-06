import angr
import claripy


def main():
    project = angr.Project('./10_angr_simprocedures')

    class mySimPro(angr.SimProcedure):
        def run(self, input_addr, input_size):
            desire_string = 'ORSDDWXHZURJRBDH'
            input_bvs = self.state.memory.load(input_addr, input_size)
            return claripy.If(input_bvs == desire_string, claripy.BVV(1, 32), claripy.BVV(0, 32))


    check_fun = 'check_equals_ORSDDWXHZURJRBDH'
    project.hook_symbol(check_fun, mySimPro())
    start_state = project.factory.entry_state()
    simulation = project.factory.simgr(start_state)

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
