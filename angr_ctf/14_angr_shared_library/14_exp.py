import angr
import claripy


def main():
    base = 0x4000000
    validate_addr, validate_return_addr = base + 0x6d7, base + 0x783
    project = angr.Project('./lib14_angr_shared_library.so', load_options = {
        'main_opts' : {
            'custom_base_addr' : base
        }
    })
    ptr, size = claripy.BVV(0x3000000, 32), claripy.BVV(8, 32)
    password = claripy.BVS('password', 8 * 8)
    start_state = project.factory.call_state(validate_addr, ptr, size)
    start_state.memory.store(ptr, password)

    simulation = project.factory.simgr(start_state)
    simulation.explore(find = validate_return_addr)
    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eax != 0)
        input = solution_state.solver.eval(password, cast_to = bytes).decode()
        print('Success: {}'.format(input))
    else:
        raise Exception('Solution not found!')


if __name__ == '__main__':
	main() 

# export LD_LIBRARY_PATH=/mnt/hgfs/payoung/Documents/ctf/angr_ctf/dist/:$LD_LIBRARY_PATH
