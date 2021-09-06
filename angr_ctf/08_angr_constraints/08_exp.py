import angr


def main():
    project = angr.Project('./08_angr_constraints')
    start_addr, check_func, buffer = 0x08048625, 0x08048565, 0x0804A050
    start_state = project.factory.blank_state(addr = start_addr)

    password = start_state.solver.BVS('password', 16 * 8)
    start_state.memory.store(buffer, password)
    start_state.regs.ebp = start_state.regs.esp
    start_state.regs.esp -= 0x18
    simulation = project.factory.simgr(start_state)

    simulation.explore(find = check_func)
    if simulation.found:
        check_state = simulation.found[0]
        except_string, check_param1, check_param2 = 'AUPDNNPROEZRJWKB', buffer, 0x10
        check_bvs = check_state.memory.load(check_param1, check_param2)
        constraint = check_bvs == except_string
        check_state.add_constraints(constraint)
        input = check_state.solver.eval(password, cast_to=bytes).decode()
        print('Success: {}'.format(input))


if __name__ == '__main__':
	main() 
