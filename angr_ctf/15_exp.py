import angr
import claripy


def main():
    project = angr.Project('./15_angr_arbitrary_read')
    
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

    def check_puts(state):
        good_job = 0x484F4A47
        param0 = state.memory.load(state.regs.esp + 4, 4, endness = project.arch.memory_endness)
        if state.se.symbolic(param0):
            is_vulnerable_expression = good_job == param0
            copied_state = state.copy()
            copied_state.add_constraints(is_vulnerable_expression)
            if copied_state.satisfiable():
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else:
            return False


    def is_good(state):
        puts_addr = 0x08048370
        if state.addr == puts_addr:
            return check_puts(state)
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
