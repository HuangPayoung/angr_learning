import angr


def main():
	project = angr.Project('./01_angr_avoid')
	initial_state = project.factory.entry_state()
	simulation = project.factory.simgr(initial_state)
	target, avoid_me = 0x080485DD, 0x080485A8
	simulation.explore(find = target, avoid = avoid_me)
	# simulation.explore(find = target)
	for solution_state in simulation.found:
		solution = solution_state.posix.dumps(0)
	print('Success: ' + solution.decode())	


if __name__ == '__main__':
	main() 
