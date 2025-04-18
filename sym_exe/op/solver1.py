import angr
import claripy
import string

global values_addr
values_addr = 0

class HookConvert(angr.SimProcedure) :

    def run(self) :
        global values_addr
        values = []

        for i in range(30) :
            var = claripy.BVS(f"var_{i}", 8)  # BVS = symbolic bit vector      =>  first 8 bits are symbolic
            fixed = claripy.BVV(0, 8 * 7)     # BVV = non-symbolic bit vector  =>  the other 56 bytes are fixed
            self.state.solver.add(var >= 0)
            self.state.solver.add(var <= 61)
            values.append(var)
            values.append(fixed)

        symbolic_bv = claripy.Concat(*values)   # instead of writing values[0], values[1], ...
        self.state.memory.store(values_addr, symbolic_bv)
        self.state.globals["symbolic_bv"] = symbolic_bv
        return 0

options = {angr.options.LAZY_SOLVES}
project = angr.Project("./100percent", auto_load_libs = False)
initial_state = project.factory.entry_state(args = ["./100percent", "AAAAAAAA"], add_options = options)
values_addr = project.loader.find_symbol("values").rebased_addr
project.hook_symbol("convert", HookConvert())
simulation = project.factory.simgr(initial_state)
simulation.explore(find = [0x400000 + 0x21c5], avoid = [0x400000 + 0x21cc])     # 0x400000 is the offset of angr

if simulation.found :
    found = simulation.found[0]
    solution = found.solver.eval(found.globals["symbolic_bv"], cast_to = bytes)
    sol = ''
    symbols = string.digits + string.ascii_letters

    for i in range(0, 30*8, 8) :
        sol += symbols[solution[i]]

    print(sol)