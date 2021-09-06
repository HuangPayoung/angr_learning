import angr


def main():
    project = angr.Project('./07_angr_symbolic_file')
    start_addr = 0x080488D6
    start_state = project.factory.blank_state(addr = start_addr)

    filename, filesize = 'OJKSQYDP.txt', 0x40
    password = start_state.solver.BVS('password', filesize * 8)
    password_file = angr.storage.SimFile(filename, content = password, size = filesize)
    start_state.fs.insert(filename, password_file)
    start_state.regs.ebp = start_state.regs.esp
    start_state.regs.esp -= 0x18
    simulation = project.factory.simgr(start_state)

    def is_good(state):
        return b'Good Job.\n' in state.posix.dumps(1)


    def is_bad(state):
        return b'Try again.\n' in state.posix.dumps(1)


    simulation.explore(find = is_good, avoid = is_bad)
    if simulation.found:
        solution_state = simulation.found[0]
        input = solution_state.solver.eval(password, cast_to=bytes).decode()
        print('Success: {}'.format(input))


if __name__ == '__main__':
	main() 
