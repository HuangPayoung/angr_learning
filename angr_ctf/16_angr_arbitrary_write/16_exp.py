import angr
import claripy


def main():
    project = angr.Project('./16_angr_arbitrary_write')
    start_state = project.factory.entry_state()
    simulation = project.factory.simgr(start_state)

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20 * 8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 'A', char <= 'Z')
            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness = project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)
            self.state.globals['solutions'] = (scanf0, scanf1)


    project.hook_symbol('__isoc99_scanf', ReplacementScanf())
    start_state = project.factory.entry_state()
    simulation = project.factory.simgr(start_state)

    def check_strncpy(state):
        password_buffer = 0x57584344
        desire_string = 'NDYNWEUJ'
        param0 = state.memory.load(state.regs.esp + 4, 4, endness = project.arch.memory_endness)
        param1 = state.memory.load(state.regs.esp + 8, 4, endness = project.arch.memory_endness)
        param2 = state.memory.load(state.regs.esp + 12, 4, endness = project.arch.memory_endness)
        src_content = state.memory.load(param1, param2)
        if state.se.symbolic(param0) and state.se.symbolic(src_content):
            does_src_hold_password = src_content[-1:-64] == desire_string
            does_dest_equal_buffer_address = param0 == password_buffer
            if state.satisfiable(extra_constraints = (does_src_hold_password, does_dest_equal_buffer_address)):
                state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
                return True
            else:
                return False
        else:
            return False


    def is_good(state):
        strncpy_addr = 0x08048410
        if state.addr == strncpy_addr:
            return check_strncpy(state)
        else:
            return False

    simulation.explore(find = is_good)
    if simulation.found:
        solution_state = simulation.found[0]
        (scanf0, scanf1) = solution_state.globals['solutions']
        input = str(solution_state.solver.eval(scanf0)) + ' ' + solution_state.solver.eval(scanf1, cast_to = bytes).decode()
        print('Success: {}'.format(input))
    else:
        raise Exception('Solution not found!')


if __name__ == '__main__':
	main() 
