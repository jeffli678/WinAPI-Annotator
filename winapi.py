import json
import re
import os
import windows_x86
import windows_x64
from binaryninja import *

MODULES = ['USER32', 'KERNEL32', 'OLE32', 'ADVAPI32']

def load_functions(module_name):
    folder = os.path.dirname(os.path.abspath(__file__)).split(user_plugin_path)[1].replace('\\','/').split("/")[1]
    function_file = open(user_plugin_path + '/' + folder + '/windows_functions/' + module_name + '.json', 'r')
    function_list = json.load(function_file)
    function_file.close()
    return function_list

def get_function_name(callee):
  module_name = re.match('(\S+)\!', callee.name)
  function_name = re.match('\S+\!(\w+)(@IAT)*?', callee.name)
  return (module_name, function_name)

def annotate(module_name, function_name, stack, function):
   if module_name.group(1) in MODULES:
      db = load_functions(module_name.group(1))
      if db.has_key(function_name.group(1)):
        stack_args = iter(stack)
        for function_arg in db[function_name.group(1)]:
          try:
            stack_instruction = stack_args.next()
            function.set_comment(stack_instruction.address, function_arg)
          except StopIteration:
            log_error('[x] Virtual Stack Empty. Unable to find function arguments for <{}>'.format(function_name))


def run_plugin(bv, function):
  # logic of stack selection
  if bv.platform.name == 'windows-x86':
    stack = windows_x86.Stack()
  elif bv.platform.name == 'windows-x86_64':
    stack = windows_x64.Stack()
  else:
    log_error('[x] Virtual stack not found for {platform}'.format(platform=bv.platform.name))
    return -1

  log_info('[*] Annotating function <{name}>'.format(name=function.symbol.name))

  stack_changing_llil =  stack.get_relevant_llil()

  for block in function.low_level_il:
    for instruction in block:
      if instruction.operation in stack_changing_llil:
        stack.update(instruction)
      if (instruction.operation == LowLevelILOperation.LLIL_CALL and
          instruction.dest.operation == LowLevelILOperation.LLIL_CONST_PTR):
        callee = bv.get_function_at(instruction.dest.constant) # Fetching function in question
        if (callee.symbol.type.name == 'ImportedFunctionSymbol'):
            module_and_function = get_function_name(callee)
            annotate(module_and_function[0], module_and_function[1], stack, function)
      elif (instruction.operation == LowLevelILOperation.LLIL_CALL):

        if (instruction.dest.operation == LowLevelILOperation.LLIL_REG and
            instruction.dest.value.type == RegisterValueType.ImportedAddressValue):
          iat_address = instruction.dest.value.value
          try:
            callee = bv.get_symbol_at(iat_address)
            if (callee.type.name == 'ImportedFunctionSymbol' or callee.type.name == 'ImportAddressSymbol'):
              module_and_function = get_function_name(callee)
              annotate(module_and_function[0], module_and_function[1], stack, function)
          except AttributeError:
            continue
        else:
          try:
            iat_address = instruction.dest.src.constant
            callee = bv.get_symbol_at(iat_address)
            if (callee.type.name == 'ImportedFunctionSymbol' or callee.type.name == 'ImportAddressSymbol'):
              module_and_function = get_function_name(callee)
              annotate(module_and_function[0], module_and_function[1], stack, function)
          except AttributeError:
            continue
        
