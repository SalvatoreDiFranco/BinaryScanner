import angr
import logging


# dizionario delle allocazioni --> key: indirizzo_allocato, value: # di byte allocati
allocated_addrs = dict()
# set (insieme) degli indirizzi deallocati
deallocated_addrs = set()


# Funzione per sopprimere i warning di angr
def suppress_angr_warnings():
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)


# Classe che definisce gli hook per le malloc
class HookMalloc(angr.SimProcedure):
    def run(self, size):
        # Chiamata a malloc di libc
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        result = self.inline_call(malloc, size).ret_expr

        addr = self.state.solver.eval(result)
        size = self.state.solver.eval(size)
        print(f"Hook malloc: a malloc function has been called")

        # Aggiunta al dizionario delle allocazioni
        allocated_addrs[addr] = size

        return result


# Classe che definisce gli hook per le free
class HookFree(angr.SimProcedure):
    def run(self, ptr):
        # Chiamata a free di libc
        free = angr.SIM_PROCEDURES['libc']['free']
        self.inline_call(free, ptr)

        # Rimozione indirizzo dal dizionario delle allozazioni e aggiunta al set delle deallocazioni
        addr = self.state.solver.eval(ptr)
        if addr in allocated_addrs:
            del allocated_addrs[addr]
            deallocated_addrs.add(addr)
            print(f"Hook free: a free function has been called")
        # Controllo presenza di double free
        elif addr in deallocated_addrs:
            print(f"Double Free detected: the free function has been called on a deallocated address!")
        return


# Funzione per hookare una malloc o una free
def hook_symbol(project, symbol, myfunction):
    hooked_addrs = set()
    for sym in project.loader.symbols:
        if symbol in sym.name and not sym.is_import:
            if sym.rebased_addr not in hooked_addrs:
                project.hook(sym.rebased_addr, myfunction)
                hooked_addrs.add(sym.rebased_addr)


# Funzione invocata ad ogni breakpoint per rilevare una lettura o una scrittura attraverso un puntatore dandling
def on_mem_access(state):
    addr = None
    write = True
    if state.inspect.mem_write_address is not None:
        addr = state.inspect.mem_write_address
    elif state.inspect.mem_read_address is not None:
        addr = state.inspect.mem_read_address
        write = False
    addr_val = state.solver.eval(addr)

    for deallocation in deallocated_addrs:
        if deallocation == addr_val:
            if write:
                print(f'Use after free detected: writing on a deallocated address!\n')
                exit(0)
            else:
                print(f'Use after free detected: reading on a deallocated address!\n')
                exit(0)


def check(binary_path):
    # Istruzioni per creare il progetto angr e lo stato iniziale della simulazione
    suppress_angr_warnings()
    try:
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    except:
        print("Path does not point to a valid binary file: " + binary_path + "\n")
        return
    init_state = project.factory.entry_state()

    # Istruzioni per impostare breakpoint di simulazione sulle azioni di lettura o scrittura in memoria
    init_state.inspect.b('mem_read', action=on_mem_access)
    init_state.inspect.b('mem_write', action=on_mem_access)

    # Istruzioni per hookare malloc e free
    hook_symbol(project, 'malloc', HookMalloc())
    hook_symbol(project, 'free', HookFree())

    # Istruzioni per creare il simulation manager e avviare l'esecuzione simbolica
    simgr = project.factory.simulation_manager(init_state)

    # simgr.run()
    while len(simgr.active) > 0:
        simgr.step()


if __name__ == '__main__':
    check('path_to_binary')
