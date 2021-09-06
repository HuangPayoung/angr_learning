import angr


def main():
	project = angr.Project('./00_angr_find')
	initial_state = project.factory.entry_state()
	simulation = project.factory.simgr(initial_state)
	target = 0x08048675
	simulation.explore(find = target)
	for solution_state in simulation.found:
		solution = solution_state.posix.dumps(0)
	print('Success: ' + solution.decode())	


if __name__ == '__main__':
	main() 
