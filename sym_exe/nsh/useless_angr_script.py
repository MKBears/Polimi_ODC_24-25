import angr
import claripy
from pwn import xor

# Trying to solve the challenge with angr, bot for some reason it stops at first iteration, better to come back to ol'good z3

global flag_len
global precomputed_table
global flag_offset

angr_offset = 0x400000
flag_len = 49
flag_offset = 0

precomputed_table = [0,
0x7FFFFFF7, 0xFFFFFFEE, 0x7FFFFFE5, 0xFFFFFFDC, 0x7FFFFFD3,
0xFFFFFFCA, 0x7FFFFFC1, 0xFFFFFFB8, 0x7FFFFFAF, 0xFFFFFFA6,
0x7FFFFF9D, 0xFFFFFF94, 0x7FFFFF8B, 0xFFFFFF82, 0x7FFFFF79,
0xFFFFFF71, 0x7FFFFF66, 0xFFFFFF5F, 0x7FFFFF54, 0xFFFFFF4D,
0x7FFFFF42, 0xFFFFFF3B, 0x7FFFFF30, 0xFFFFFF29, 0x7FFFFF1E,
0xFFFFFF17, 0x7FFFFF0C, 0xFFFFFF05, 0x7FFFFEFA, 0xFFFFFEF3,
0x7FFFFEE8, 0xFFFFFEE2, 0x7FFFFED5, 0xFFFFFECC, 0x7FFFFEC7,
0xFFFFFEBE, 0x7FFFFEB1, 0xFFFFFEA8, 0x7FFFFEA3, 0xFFFFFE9A,
0x7FFFFE8D, 0xFFFFFE84, 0x7FFFFE7f, 0xFFFFFE76, 0x7FFFFE69,
0xFFFFFE60, 0x7FFFFE5B, 0xFFFFFE53, 0x7FFFFE44, 0xFFFFFE3D,
0x7FFFFE36, 0xFFFFFE2F, 0x7FFFFE20, 0xFFFFFE19, 0x7FFFFE12,
0xFFFFFE0B, 0x7FFFFDFC, 0xFFFFFDF5, 0x7FFFFDEE, 0xFFFFFDE7,
0x7FFFFDD8, 0xFFFFFDD1, 0x7FFFFDCA, 0xFFFFFDC4, 0x7FFFFDB3,
0xFFFFFDAA, 0x7FFFFDA1, 0xFFFFFD98, 0x7FFFFD97, 0xFFFFFD8E,
0x7FFFFD85, 0xFFFFFD7C, 0x7FFFFD6B, 0xFFFFFD62, 0x7FFFFD59,
0xFFFFFD50, 0x7FFFFD4F, 0xFFFFFD46, 0x7FFFFD3D, 0xFFFFFD35,
0x7FFFFD22, 0xFFFFFD1B, 0x7FFFFD10, 0xFFFFFD09, 0x7FFFFD06,
0xFFFFFCFF, 0x7FFFFCF4, 0xFFFFFCED, 0x7FFFFCDA, 0xFFFFFCD3,
0x7FFFFCC8, 0xFFFFFCC1, 0x7FFFFCBE, 0xFFFFFCB7, 0x7FFFFCAC,
0xFFFFFCA6, 0x7FFFFC91, 0xFFFFFC88, 0x7FFFFC83, 0xFFFFFC7A,
0x7FFFFC75, 0xFFFFFC6C, 0x7FFFFC67, 0xFFFFFC5E, 0x7FFFFC49,
0xFFFFFC40, 0x7FFFFC3B, 0xFFFFFC32, 0x7FFFFC2D, 0xFFFFFC24,
0x7FFFFC1F, 0xFFFFFC17, 0x7FFFFC00, 0xFFFFFBF9, 0x7FFFFBF2,
0xFFFFFBEB, 0x7FFFFBE4, 0xFFFFFBDD, 0x7FFFFBD6, 0xFFFFFBCF,
0x7FFFFBB8, 0xFFFFFBB1, 0x7FFFFBAA, 0xFFFFFBA3, 0x7FFFFB9C,
0xFFFFFB95, 0x7FFFFB8E, 0xFFFFFB88, 0x7FFFFB7f, 0xFFFFFB66,
0x7FFFFB6D, 0xFFFFFB54, 0x7FFFFB5B, 0xFFFFFB42, 0x7FFFFB49,
0xFFFFFB30, 0x7FFFFB27, 0xFFFFFB2E, 0x7FFFFB15, 0xFFFFFB1C,
0x7FFFFB03, 0xFFFFFB0A, 0x7FFFFAF1, 0xFFFFFAF9, 0x7FFFFAEE,
0xFFFFFAD7, 0x7FFFFADC, 0xFFFFFAC5, 0x7FFFFACA, 0xFFFFFAB3,
0x7FFFFAB8, 0xFFFFFAA1, 0x7FFFFA96, 0xFFFFFA9F, 0x7FFFFA84,
0xFFFFFA8D, 0x7FFFFA72, 0xFFFFFA7B, 0x7FFFFA60, 0xFFFFFA6A,
0x7FFFFA5D, 0xFFFFFA44, 0x7FFFFA4F, 0xFFFFFA36, 0x7FFFFA39,
0xFFFFFA20, 0x7FFFFA2B, 0xFFFFFA12, 0x7FFFFA05, 0xFFFFFA0C,
0x7FFFF9F7, 0xFFFFF9FE, 0x7FFFF9E1, 0xFFFFF9E8, 0x7FFFF9D3,
0xFFFFF9DB, 0x7FFFF9CC, 0xFFFFF9B5, 0x7FFFF9BE, 0xFFFFF9A7,
0x7FFFF9A8, 0xFFFFF991, 0x7FFFF99A, 0xFFFFF983, 0x7FFFF974,
0xFFFFF97D, 0x7FFFF966, 0xFFFFF96F, 0x7FFFF950, 0xFFFFF959,
0x7FFFF942, 0xFFFFF94C, 0x7FFFF93B, 0xFFFFF922, 0x7FFFF929,
0xFFFFF910, 0x7FFFF91F, 0xFFFFF906, 0x7FFFF90D, 0xFFFFF8F4,
0x7FFFF8E3, 0xFFFFF8EA, 0x7FFFF8D1, 0xFFFFF8D8, 0x7FFFF8C7,
0xFFFFF8CE, 0x7FFFF8B5, 0xFFFFF8BD, 0x7FFFF8AA, 0xFFFFF893,
0x7FFFF898, 0xFFFFF881, 0x7FFFF88E, 0xFFFFF877, 0x7FFFF87C,
0xFFFFF865, 0x7FFFF852, 0xFFFFF85B, 0x7FFFF840, 0xFFFFF849,
0x7FFFF836, 0xFFFFF83F, 0x7FFFF824, 0xFFFFF82E, 0x7FFFF819,
0xFFFFF800, 0x7FFFF80B, 0xFFFFF7f2, 0x7FFFF7fD, 0xFFFFF7E4,
0x7FFFF7EF, 0xFFFFF7D6, 0x7FFFF7C1, 0xFFFFF7C8, 0x7FFFF7B3,
0xFFFFF7BA, 0x7FFFF7A5, 0xFFFFF7AC, 0x7FFFF797, 0xFFFFF79F,
0x7FFFF788, 0xFFFFF771, 0x7FFFF77A, 0xFFFFF763, 0x7FFFF76C,
0xFFFFF755, 0x7FFFF75E, 0xFFFFF747, 0x7FFFF730, 0xFFFFF739,
0x7FFFF722, 0xFFFFF72B, 0x7FFFF714, 0xFFFFF71D, 0]
    
class HookXhashe(angr.SimProcedure):
    IS_FUNCTION = True

    def init_input(self):
        global flag_len
        global flag_offset

        flag = []

        for i in range(flag_len):
            c = claripy.BVS('arg', 8)
            self.state.solver.add(c > 0x40)
            self.state.solver.add(c < 0x7F)
            flag.append(c)

        symbolic_bv = claripy.Concat(*flag)
        self.state.memory.store(flag_offset, symbolic_bv)
        self.state.globals["symbolic_bv"] = symbolic_bv
        print(f'Symbolic bv stored to {hex(flag_offset)}')

    def run(self, flag_vec, iterations, initial):
        global precomputed_table
        global flag_offset

        s = flag_vec.concrete_value
        print('-------------------------------')
        print(f'flag_vec = {hex(s)}')

        if flag_offset == 0:
            flag_offset = s
            print(f'argv address: {hex(flag_offset)}')
            self.init_input()

        n = iterations.concrete_value

        if type(n) is not int:
            n = min(flag_offset + flag_len - s, 4)

        print(f'Iterations = {n}')
        hash = initial.concrete_value.to_bytes(4, 'little')
        print(f'Initial hash = {hash}')

        for i in range(n):
            sym = self.state.mem[s + i]
            sym = sym.uint8_t.concrete
            print(f'sym = {chr(sym)}')
            tab_index = int.from_bytes(xor(sym, hash[3], cut=1), 'little')
            print(f'tab_index = {tab_index}')
            factor = int.from_bytes(hash, 'little')<<8
            # print(f'Shifted factor = {hex(factor)}')
            factor = factor.to_bytes(5, 'little')[:4]
            # print(f'Trimmed factor = {factor}')
            tab_val = precomputed_table[tab_index].to_bytes(4, 'little')
            print(f'tab_val = {tab_val}')
            hash = xor(tab_val, factor, cut=4)
            print(f'hash = {hash}')

        hash = int.from_bytes(hash, 'little')
        print(f'Cast hash = {hex(hash)}')
        # bvv = claripy.BVV(hash, 64)
        # self.state.regs.rax = bvv
        return hash # bvv

class HookXhasheSlow(angr.SimProcedure):
    IS_FUNCTION = True
    
    def run(self):
        print('Skipping function xhashe_slow')
        return 0

options = {angr.options.LAZY_SOLVES}
project = angr.Project('./notsohandy', auto_load_libs=False)
initial_state = project.factory.entry_state(args=['./notsohandy', 'A'*flag_len], add_options=options)

project.hook_symbol('xhashe', HookXhashe())             # substituting function xhashe with the hook
project.hook_symbol('xhashe_slow', HookXhasheSlow())    # substituting function xhashe_slow with the hook

simulation = project.factory.simgr(initial_state)
simulation.explore(find=[angr_offset + 0x1422], avoid=[angr_offset + 0x13DC, angr_offset + 0x1433])

if simulation.found:
    found = simulation.found[0]
    solution = found.solver.eval(found.globals["symbolic_bv"], cast_to = bytes)
    print(solution.decode('utf-8'))
else:
    print('Couldn\'t find a solution.')