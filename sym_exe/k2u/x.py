import angr
import claripy

# The code for the constraints on the sudoku cells has been taken from z3 python API gide (https://ericpony.github.io/z3py-tutorial/guide-examples.htm) and adapted to support claripy

class HookGetchar(angr.SimProcedure):
    # Making the program skip the getchar calls
    def run(self):
        pass

def Distinct(vec, solver):
    for i in range(9):
        for j in range(i+1, 9):
            solver.add(vec[i] != vec[j])

exe = './kudos2u'
options = {angr.options.LAZY_SOLVES}
project = angr.Project(exe, auto_load_libs = False)
initial_state = project.factory.entry_state(args = [exe], add_options = options)
project.hook_symbol('getchar', HookGetchar())   # substituting function getchar with the hook
grid_addr = project.loader.find_symbol('grid').rebased_addr

# 9x9 matrix of integer variables
X = [[claripy.BVS(f'x_{i+1}_{j+1}', 8) for j in range(9)] for i in range(9)]
print('Created vector of symbols (grid)')

# each cell contains a value in {1, ..., 9}
for i in range(9):
    for j in range(9):
        initial_state.solver.add(claripy.And(0 <= X[i][j], X[i][j] <= 8))       # Between '1'-48 and '9'-48 ('1'-'0' and '9'-'0')

print('Added values constraints')

# each row contains a digit at most once
for i in range(9):
    Distinct(X[i], initial_state.solver)
    
print('Added row constraints')

# each column contains a digit at most once
for j in range(9):
    Distinct([X[i][j] for i in range(9)], initial_state.solver)
    
print('Added clumn constraints')

# each 3x3 square contains a digit at most once
for i0 in range(3):
    for j0 in range(3):
        Distinct([ X[3*i0 + i][3*j0 + j] for i in range(3) for j in range(3)], initial_state.solver)
        
print('Added square constraints')

vec = [claripy.Concat(*X[i]) for i in range(9)]
symbolic_bv = claripy.Concat(*vec)
initial_state.memory.store(grid_addr, symbolic_bv)
initial_state.globals["symbolic_bv"] = X
print('Created symbolic BV for gri')

simulation = project.factory.simgr(initial_state)
print('Starting simulation')
simulation.explore(find = [0x400000 + 0x161A], avoid = [0x400000 + 0x1A4D])     # 0x400000 is the offset of angr

if simulation.found :
    found = simulation.found[0]
    solution = found.solver.eval(found.globals['symbolic_bv'], cast_to = bytes).decode()
    print(solution)
else:
    print('Could\'t find a solution')