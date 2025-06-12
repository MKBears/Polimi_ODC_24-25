import z3
import angr
import claripy

# The code for solving the sudoku is very kindly offered by the z3 python API guide (https://ericpony.github.io/z3py-tutorial/guide-examples.htm), I only changed the initial configuration, taking it from the global variable grid.

# 9x9 matrix of integer variables
X = [ [ z3.Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ]
      for i in range(9) ]

# each cell contains a value in {1, ..., 9}
cells_c  = [ z3.And(1 <= X[i][j], X[i][j] <= 9)
             for i in range(9) for j in range(9) ]

# each row contains a digit at most once
rows_c   = [ z3.Distinct(X[i]) for i in range(9) ]

# each column contains a digit at most once
cols_c   = [ z3.Distinct([ X[i][j] for i in range(9) ])
             for j in range(9) ]

# each 3x3 square contains a digit at most once
sq_c     = [ z3.Distinct([ X[3*i0 + i][3*j0 + j]
                        for i in range(3) for j in range(3) ])
             for i0 in range(3) for j0 in range(3) ]

sudoku_c = cells_c + rows_c + cols_c + sq_c

# sudoku instance, we use '0' for empty cells
instance = (
    (0, 3, 0, 7, 0, 0, 2, 0, 0),
    (0, 0, 0, 0, 5, 1, 8, 7, 0),
    (8, 0, 9, 4, 0, 0, 0, 0, 0),
    (3, 0, 0, 0, 0, 0, 0, 5, 4),
    (6, 0, 0, 2, 1, 0, 0, 0, 0),
    (9, 0, 7, 0, 0, 6, 0, 0, 0),
    (0, 1, 2, 0, 8, 0, 5, 0, 0),
    (0, 0, 0, 1, 2, 0, 7, 0, 8),
    (0, 9, 0, 0, 3, 5, 0, 1, 0))

instance_c = [ z3.If(instance[i][j] == 0,
                  True,
                  X[i][j] == instance[i][j])
               for i in range(9) for j in range(9) ]

s = z3.Solver()
s.add(sudoku_c + instance_c)
if s.check() == z3.sat:
    m = s.model()
    r = [ [ m.evaluate(X[i][j]) for j in range(9) ]
          for i in range(9) ]
    z3.print_matrix(r)
else:
    print ("failed to solve")

exploit = ''

for i in range(9):
    for j in range(9):
        if instance[i][j] == 0:
            exploit += str(r[i][j])

print('First part of the exploit: ' + exploit)
# exit(0)


# Then the program reads other 47 chars, but this time without constraints (reads them all together)
# Hijack SYS_read to make it store the symbolic_bv, take the address from the syscall args

class HookGetchar(angr.SimProcedure):
    NO_RET = False
    IS_FUNCTION = True

    def run(self):
        i = self.state.regs.rcx.concrete_value
        c = int(exploit[i])
        print(f'Reading {c} (r[{i}])')

        return c + 48
        return claripy.BVV(c + 48, 8)

class HookMmap(angr.SimProcedure):
    NO_RET = False
    IS_FUNCTION = True

    def run(self):
        global addr
        print('Mmapping')
        self.state.memory.map_region(addr, 0x2000, 7)  # rwx
        return claripy.BVV(addr, 64)
    
class HookMemcpy(angr.SimProcedure):
    NO_RET = False
    IS_FUNCTION = True

    def run(self):
        global addr
        global shellcode_addr
        print('Mecpying')
        data = self.state.memory.load(shellcode_addr, 0xb60)
        self.state.memory.store(addr + 0x1000, data)
        return claripy.BVV(addr, 64)

class Hijack(angr.SimProcedure):
    NO_RET = True
    IS_FUNCTION = False

    def run(self):
        global simgr
        print('Hijacking execution')
        print(hex(self.state.regs.rip.concrete_value))
        self.state.regs.rip = addr + 0x1000

class HookRead(angr.SimProcedure):
    NO_RET = False
    IS_FUNCTION = False
    IS_SYSCALL = True

    def run(self):
        print('Entered read syscall')
        dest = self.state.regs.rsi
        values = [claripy.BVS(f'In_{i}', 8) for i in range(47)]

        for i in range(47):
            self.state.solver.add(claripy.And(0x20 <= values[i], values[i] < 0x7f))

        symbolic_bv = claripy.Concat(*values)
        self.state.memory.store(dest, symbolic_bv)
        self.state.globals["symbolic_bv"] = symbolic_bv
        print('Stored symbolic BV')
        return 47
    
def show_syscall(state):
    #print(f'Wrote {state.inspect.mem_write_length} Bytes to address {state.inspect.mem_write_address}')
    print(state.inspect.syscall_name)

def check_ip(state):
    global simgr
    ip = state.addr
    if ip == 0x4015fb:
        simgr.step()
        print(f'Next instruction @{hex(state.regs.rip.concrete_value)}')

class GetRax(angr.SimProcedure):
    IS_FUNCTION = False
    NO_RET = True
    IS_SYSCALL = False

    def run(self):
        global project
        ptr = self.state.regs.rax.concrete_value
        print(f'ptr = {hex(ptr)}')
        project.hook(ptr + 0xf7 - 0x80, HookRead(), 2)

class GetRdx(angr.SimProcedure):
    # IS_FUNCTION = False
    # NO_RET = True
    # IS_SYSCALL = False

    def run(self):
        ptr = self.state.regs.rdx.concrete_value
        print(f'Calling {hex(ptr)}')

exe = './kudos2u'
options = {angr.options.LAZY_SOLVES}
project = angr.Project(exe, auto_load_libs = False)
initial_state = project.factory.entry_state(add_options = options)
simgr = project.factory.simulation_manager(initial_state)
# project.hook_symbol('getchar', HookGetchar(), replace=True)   # substituting function getchar with the hook
project.hook_symbol('mmap', HookMmap(), replace=True)
project.hook_symbol('memcpy', HookMemcpy(), replace=True)
initial_state.inspect.b('instruction', when=angr.BP_BEFORE, action=check_ip)
# project.hook(0x400000 + 0x15FB, Hijack(), 2)
# project.hook(0x400000 + 0x15b7, GetRax())
# project.hook(0x400000 + 0x15FB, GetRdx())
# project.hook(0xc0081077, HookRead(), 2)

# initial_state = project.factory.blank_state(address=400000+0x158B)
# initial_state.regs.rsp = 0x600000
initial_state.inspect.b('syscall', when=angr.BP_BEFORE, action=show_syscall)
grid_addr = project.loader.find_symbol('grid').rebased_addr
shellcode_addr = project.loader.find_symbol('shellcode').rebased_addr
addr = 0xdead0000

# 9x9 matrix of integer variables
values = [[claripy.BVV(r[i][j].as_long(), 8) for j in range(9)] for i in range(9)]
print('Created vector of values (grid)')

vec = [claripy.Concat(*values[i]) for i in range(9)]
grid = claripy.Concat(*vec)
initial_state.memory.store(grid_addr, grid)
print('Stored grid values')

simulation = project.factory.simgr(initial_state)
print('Starting simulation')
simulation.explore(find=[0x400000 + 0x161A], avoid=[0x400000 + 0x1A4D])     # 0x400000 is te offset of angr

if simulation.found:
    found = simulation.found[0]
    solution = found.solver.eval(found.globals['symbolic_bv'], cast_to = bytes).decode()
    print(solution)
else:
    print('Could\'t find a solution')

# brva 0x138B
# brva 0x1423
# brva 0x1558

# 0xf7-0x80 -> SYS_read call address
# addr returned by mmap + 0x1c00 -> buffer of read syscall