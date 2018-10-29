import json
import os
from binaryninja import LowLevelILOperation, PluginCommand
from sys import exc_info

calls = [
  LowLevelILOperation.LLIL_CALL,
  LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
]

registers = [
  'rax',
  'rbx',
  'rcx',
  'rdx',
  'rsi',
  'rdi',
  'r8',
  'r9',
  'r10',
  'r11',
  'r12',
  'r13',
  'r14',
  'r15',
  'eax',
  'ebx',
  'ecx',
  'edx',
  'edi',
  'esi'
]

x64_convention = [
  'rcx',
  'rdx',
  'r8',
  'r9',
  'ecx',
  'edx',
  'r8d',
  'r9d'
]

class FunctionObj:
    name = ''
    argc = 0
    param_names = []

    def __init__(self, api_func, args, names):
        self.name = api_func
        self.argc = args
        self.param_names = names

def annotate_x64(obj, curr_index, function, sorted_llil):
    i = 0
    j = curr_index
    while (i < obj.argc):
        if (i < 4):
            if sorted_llil[j - 1].operation.value == 1 and str(sorted_llil[j - 1].dest) in x64_convention:
                reg = x64_convention.index(str(sorted_llil[j - 1].dest))
                if (reg > 3):
                    reg -= 4
                function.set_comment(sorted_llil[j - 1].address, obj.param_names[reg])
                i += 1
        else:
            if sorted_llil[j - 1].operation.value == 8:
                function.set_comment(sorted_llil[j - 1].address, obj.param_names[i])
                i += 1
        j -= 1

def annotate_x86(obj, curr_index, function, sorted_llil):
    i = 0
    j = curr_index
    while (i < obj.argc):
        if sorted_llil[j - 1].operation.value == 8:
            function.set_comment(sorted_llil[j - 1].address, obj.param_names[i])
            i += 1
        j -= 1

def get_func_attr(func):
    i = 0
    params = []

    data_dir = os.path.dirname(os.path.realpath(__file__)) 

    with open(data_dir + '/data.json', 'r') as data_file:
        json_data = json.load(data_file)
        data_file.close()

    try:
        argc = json_data['func.' + func + '.args']
        while (i < argc):
            params.append(json_data['func.' + func + '.arg.' + str(i)])
            i += 1
        obj = FunctionObj(func, argc, params)
    except:
        print("[*] ERROR: no parameter data for " + func + " [*]")
        obj = FunctionObj(func, -1, params)

    return obj

def find_func(index, function):
    found = 0
    j = index
    llil = function.low_level_il
    dst = str(llil[j].dest)

    while (found == 0):
        if llil[j - 1].operation.value == 1 and str(llil[j - 1].dest) == dst:
            symbol = bv.get_symbol_at(llil[j - 1].dest.value.value)
        j -= 1

    return symbol

def initialize(bv, function):
    """This function orders the llil instructions
    by address
    """

    sorted_llil = []
    zipped_llil = []
    instructions = []
    addrs = []
    
    for block in function.low_level_il:
        for instr in block:
            instructions.append(instr)
            addrs.append(instr.address)
    
    zipped_llil = zip(addrs, instructions)
    zipped_llil.sort()
    sorted_llil = [instructions for addrs, instructions in zipped_llil]

    return sorted_llil 

def run_plugin(bv, function):

    curr_index = 0
    symbol = None

    sorted_llil = initialize(bv, function)

    for instr in sorted_llil:
        if instr.operation in calls:
            if (instr.dest.value.type.value != 0):
                symbol = bv.get_symbol_at(instr.dest.value.value)
            else: 
                symbol = -1
            if symbol > 0:
                try:
                    if (symbol.type.value == 1 or symbol.type.value == 2):
                        winapi_name = symbol.name.split('@')[0]
                        if str(instr.dest) in registers:
                            function.set_comment(instr.address, winapi_name + '()')
                        func_obj = get_func_attr(winapi_name)
                        if func_obj.argc > 0:
                            if bv.platform.name == 'windows-x86':
                                annotate_x86(func_obj, curr_index, function, sorted_llil)
                            if bv.platform.name == 'windows-x86_64':
                                annotate_x64(func_obj, curr_index, function, sorted_llil)
                except:
                    e = exc_info()[0]
                    print(e)
              
        curr_index += 1

