import angr


def main():
    project = angr.Project('./02_angr_find_condition')
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


if __name__ == '__main__':
	main() 
