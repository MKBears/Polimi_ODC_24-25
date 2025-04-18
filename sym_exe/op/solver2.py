import angr
import claripy
import string

options = {angr.options.LAZY_SOLVES}
project = angr.Project("./100percent", auto_load_libs = False)
check_function_addr = project.loader.find_symbol("check").rebased_addr
initial_state = project.factory.blank_state(addr = check_function_addr, add_options = options)
initial_state.regs.rsp = 0x600000
values_addr = project.loader.find_symbol("values").rebased_addr
values = []

for i in range(30) :
    var = claripy.BVS(f"var_{i}", 8)            # BVS = symbolic bit vector      =>  first 8 bits are symbolic
    fixed = claripy.BVV(0, 8 * 7)     # BVV = non-symbolic bit vector  =>  the other 56 bytes are fixed
    initial_state.solver.add(var >= 0)
    initial_state.solver.add(var <= 61)
    values.append(var)
    values.append(fixed)

symbolic_bv = claripy.Concat(*values)   # instead of writing values[0], values[1], ...
initial_state.memory.store(values_addr, symbolic_bv)
initial_state.globals["symbolic_bv"] = symbolic_bv

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