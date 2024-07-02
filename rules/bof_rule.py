import angr
from angr import sim_options
import psutil, os, claripy, logging


def suppress_angr_warnings():
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)


def checkWriteStackMem(cur_state: angr.SimState):
    stack_pointer = hex(cur_state.callstack.current_stack_pointer)
    base_pointer = hex(cur_state.solver.eval(cur_state.regs.bp))
    for act in cur_state.history.actions:
        if (act.type == 'mem') \
                and (act.action == 'write') \
                and (base_pointer >= hex(act.actual_addrs[0]) >= stack_pointer) \
                and isinstance(act.data.ast, claripy.ast.bv.BV):
            return True
    return False


def check(file_name):
    print("Checking STACK OVERFLOW")
    project = angr.Project(file_name, auto_load_libs=False)
    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP,
                    sim_options.TRACK_MEMORY_ACTIONS,
                    sim_options.TRACK_MEMORY_MAPPING,
                    sim_options.TRACK_ACTION_HISTORY,
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    init_state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.DFS())

    while simgr.active:
        simgr.move(filter_func=checkWriteStackMem,
                   from_stash='active', to_stash='symbolic_writed_stack')
        if hasattr(simgr, 'symbolic_writed_stack'):
            while simgr.symbolic_writed_stack:
                simgr.step('symbolic_writed_stack')
                if simgr.unconstrained:
                    for unconstrained_state in simgr.unconstrained:
                        #print(type(unconstrained_state.ip))
                        print("Buffer Overflow detected!")
                        #print("Buffer pointer at overflow:", hex(unconstrained_state.callstack.current_stack_pointer))
                        #print("Payload causing overflow:", unconstrained_state.posix.dumps(0))
                        print("Memory consumed: %.4f MB" % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024))
                    return
        simgr.step('active')
    print("No Buffer Overflow detected!")


if __name__ == '__main__':
    suppress_angr_warnings()
    check('path_to_binary')
