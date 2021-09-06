import angr
import claripy


def main():
    project = angr.Project('./11_angr_sim_scanf')
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
