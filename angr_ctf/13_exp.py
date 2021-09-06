import angr
import claripy


def main():
    project = angr.Project('./13_angr_static_binary')

    printf_addr = 0x0804ED40
    scanf_addr = 0x0804ED80
    strcmp_addr = 0x08048280
    puts_addr = 0x0804F350
    __libc_start_main_addr = 0x08048D10
    project.hook(printf_addr, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(scanf_addr, angr.SIM_PROCEDURES['libc']['scanf']())
    project.hook(strcmp_addr, angr.SIM_PROCEDURES['libc']['strcmp']())
    project.hook(puts_addr, angr.SIM_PROCEDURES['libc']['puts']())
    project.hook(__libc_start_main_addr, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
    
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
