import angr
from angr import SimProcedure
import re
import logging


def suppress_angr_warnings():
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)


class MyInputFunction(SimProcedure):
    def run(self, dst):
        input_size = 50
        sym_input = self.state.solver.BVS("sym_input", input_size * 8)
        self.state.memory.store(dst, sym_input)
        self.state.solver.add(sym_input.get_byte(input_size - 1) == 0)
        return input_size


class MyVulFunction(SimProcedure):
    def checkFSB(self):
        fmt_str = self.state.memory.load(self.state.solver.eval(self.arguments[0]), size=bits)
        if fmt_str.symbolic:
            return True
        return False

    def run(self, fmt):
        if self.checkFSB():
            print("Vulnerable function found")
            return 0
        else:
            print("Vulnerable function NOT found!")


def hook_vuln_functions(project):
    flag = False
    for vulfunc_sym in project.loader.symbols:
        if 'printf' in vulfunc_sym.name:
            project.hook(vulfunc_sym.rebased_addr, MyVulFunction())
            flag = True
    return flag


def hook_input_functions(project):
    for infunc_sym in project.loader.symbols:
        pattern = re.compile(r'get|scan|read')
        if pattern.search(infunc_sym.name):
            project.hook(infunc_sym.rebased_addr, MyInputFunction())
    return


def hooked_functions(project):
    for sym in project.loader.symbols:
        print(f"Symbol: {sym.name}, Hooked: {project.is_symbol_hooked(sym.rebased_addr)}")


def check(binary_file):
    try:
        project = angr.Project(binary_file, load_options={'auto_load_libs': False})
    except:
        print("Path does not point to a valid binary file: " + binary_file + "\n")
        return
    if not hook_vuln_functions(project):
        print('No vulnerable functions founded and hooked!')
        return
    hook_input_functions(project)

    global bits
    bits = project.arch.bits

    state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.DFS())
    simgr.run()


if __name__ == '__main__':
    suppress_angr_warnings()
    check('/Users/salvo/PycharmProjects/BinaryScanner/test/fsb/no_fsb_vuln')
