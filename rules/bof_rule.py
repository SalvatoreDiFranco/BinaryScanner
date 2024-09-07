import angr
from angr import sim_options
import psutil, os, claripy, logging

# Funzione per sopprimere i warning di angr
def suppress_angr_warnings():
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)


# Funzione per controllare se nello storico delle azioni di uno stato
# sono state eseguite delle scritture simboliche sullo stack durante l'esecuzione
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


def check(binary_file):
    # Codice per creare il progetto angr e il simulation manager
    try:
        project = angr.Project(binary_file, auto_load_libs=False)
    except:
        print("Path does not point to a valid binary file: " + binary_file + "\n")
        return
    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP,
                    sim_options.TRACK_MEMORY_ACTIONS,
                    sim_options.TRACK_MEMORY_MAPPING,
                    sim_options.TRACK_ACTION_HISTORY,
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    init_state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.DFS())

    # Ciclo while per i passi dell'esecuzione simbolica
    while simgr.active:
        # Popolare la pila degli stati con scrittura sullo stack nello storico
        simgr.move(filter_func=checkWriteStackMem,
                   from_stash='active', to_stash='symbolic_writed_stack')
        # Per ciascuno stato nella pila symbolic_writed_stack si procede con l'esecuzione
        if hasattr(simgr, 'symbolic_writed_stack'):
            while simgr.symbolic_writed_stack:
                simgr.step('symbolic_writed_stack')
                if simgr.unconstrained:
                    # Per ogni stato non vincolato, se il valore del program counter è simbolico
                    # (= potenzialmente uguale a 0x43434343) allora ho uno stato che potenzialmente
                    # segnala un buffer overflow sullo stack
                    for unconstrained_state in simgr.unconstrained:
                        if unconstrained_state.satisfiable(extra_constraints=[unconstrained_state.regs.pc == 0x43434343]):
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
