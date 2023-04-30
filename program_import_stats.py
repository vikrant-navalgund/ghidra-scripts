import os
from ghidra.program.flatapi import FlatProgramAPI

# Suspicious functions
vuln_funcs = ['CryptEncrypt', 
              'CryptDecrypt', 
              'HttpSendRequestA',
              'InternetReadFile',
              'RegSetValueExA',
              'RegOpenKeyExA',
              'RegDeleteValueA' ]

program = getState().getCurrentProgram()
bin_path = program.getExecutablePath()

print()
print(f"[>] program -> {os.path.basename(bin_path)}")

# Process the symbol table
symbol_table = program.getSymbolTable()
symbol_itr = symbol_table.getExternalSymbols()

check_call = lambda ref : ref.getReferenceType().isCall()

print("[>] Imported suspicious functions/symbols")

while symbol_itr.hasNext():
    sym = symbol_itr.next()
    name = sym.getName()
    addr = sym.getAddress()
    refs = sym.getReferences()
    
    refs = ['0x' + ref.getFromAddress().toString() for ref in filter(check_call, refs)]
    
    if name in vuln_funcs:
        print(f"\t[>] {name} - CALL -> {refs}".expandtabs(2))

print()
#print(f"[>] {currentAddress} -> {getInstructionAt(currentAddress)}")
