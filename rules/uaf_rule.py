import angr
import logging

allocated_addrs = dict()
deallocated_addrs = set()


def suppress_angr_warnings():
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)


class HookMalloc(angr.SimProcedure):
    def run(self, size):
        # Chiamata a malloc originale
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        result = self.inline_call(malloc, size).ret_expr

        addr = self.state.solver.eval(result)
        size = self.state.solver.eval(size)
        print(f"Hook malloc: allocated {size} bytes at address {hex(addr)}")
        allocated_addrs[addr] = size

        return result


class HookFree(angr.SimProcedure):
    def run(self, ptr):
        # Chiamata a free originale
        free = angr.SIM_PROCEDURES['libc']['free']
        self.inline_call(free, ptr)

        # Ottieni l'indirizzo del puntatore liberato
        addr = self.state.solver.eval(ptr)
        if addr in allocated_addrs:
            del allocated_addrs[addr]
            deallocated_addrs.add(addr)
            print(f"Hook free: freed memory at address {hex(addr)}")
        elif addr in deallocated_addrs:
            print(f"Hook free: double free vulnerability detected at address {hex(addr)}")
        return


def hook_symbol(project, symbol, myfunction):
    hooked_addrs = set()
    for sym in project.loader.symbols:
        if symbol in sym.name and not sym.is_import:
            if sym.rebased_addr not in hooked_addrs:
                project.hook(sym.rebased_addr, myfunction)
                hooked_addrs.add(sym.rebased_addr)


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
                print(f'Use after free detected: writing on the deallocated address {hex(addr_val)}')
                exit(0)
            else:
                print(f'Use after free detected: reading on the deallocated address {hex(addr_val)}')
                exit(0)


def check(binary_path):
    try:
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    except:
        print("Path does not point to a valid binary file: " + binary_path + "\n")
        return

    init_state = project.factory.entry_state()

    init_state.inspect.b('mem_read', action=on_mem_access)
    init_state.inspect.b('mem_write', action=on_mem_access)

    hook_symbol(project, 'malloc', HookMalloc())
    hook_symbol(project, 'free', HookFree())

    simgr = project.factory.simulation_manager(init_state)

    while len(simgr.active) > 0:
        simgr.step()


if __name__ == '__main__':
    suppress_angr_warnings()
    check('path_to_binary')
