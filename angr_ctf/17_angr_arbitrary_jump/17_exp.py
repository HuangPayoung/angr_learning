import angr
import claripy


def main():
    project = angr.Project('./17_angr_arbitrary_jump')
    print_good = 0x42585249
    start_state = project.factory.entry_state()
    simulation = project.factory.simgr(
        start_state,
        save_unconstrained = True,
        stashes = {
            'active' : [start_state],
            'unconstrained' : [],
            'found' : [],
            'not_needed' : []
        }
    )

    def has_acitve():
        return simulation.active

    def has_unconstrained():
        return simulation.unconstrained

    def has_found():
        return simulation.found

    while (has_acitve() or has_unconstrained()) and (not has_found()):
        for unconstrained in simulation.unconstrained:
            eip = unconstrained.regs.eip
            if unconstrained.satisfiable(extra_constraints = [(eip == print_good)]):
                simulation.found.append(unconstrained)
                unconstrained.add_constraints(eip == print_good)
                break
        simulation.drop(stash='unconstrained')
        simulation.step()
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eip == print_good)
        for byte in solution_state.posix.stdin.content[0][0].chop(bits = 8):
            solution_state.add_constraints(byte >= ord('A'), byte <= ord('Z'))
        input = solution_state.posix.dumps(0).decode()
        print('Success: {}'.format(input))
    else:
        raise Exception('Solution not found!')


if __name__ == '__main__':
	main() 
