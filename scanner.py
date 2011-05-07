from __future__ import with_statement
import hashlib
from functools import wraps
import os
import sys
import cPickle
sys.path.append(r'C:\pyemu')
sys.path.append(r'C:\pyemu\lib')

try:
    from PyEmu import PEPyEmu
except:
    print "PyEmu not found"
    sys.exit(1)
import time

DEBUG=0

""" Check the beginning of the file with two hashes """
def hashfile(path):
    m = hashlib.sha256()
    with file(path) as f:
        while True:
            d = f.read(8096)
            if not d:
                break
            m.update(d) 	  
    return m.hexdigest()

class HashCache(object):
    hashes = {}

    def __init__(self):
        if os.path.exists('hashcache.dat'):
            with file('hashcache.dat', 'rb') as f:
                self.hashes=cPickle.load(f)

    def add_hash(self, filehash, malicious):
        self.hashes[filehash] = malicious
        with file('hashcache.dat', 'wb') as f:
            cPickle.dump(self.hashes, f)

    def check_hash(self, filehash):
        if filehash in self.hashes.keys():
            return self.hashes[filehash]

def timing(func):
    '''Timing decorator that prints execution time of the wrapped function'''
    @wraps(func)
    def wrapper(*arg):
        begin = time.time()
        result = func(*arg)
        end = time.time()
        print '%s executed for %0.3f ms' % (func.func_name, (end-begin)*1000.0)
        return result
    return wrapper

""" Stop when the PC reaches this """
def pc_exit_handler(emu, EIP):
    emu.emulating=False
    return False

"""
Keep track of all modified addresses in code.

Set a handler to immediately exit when these are accessed.
"""
def code_base_write_handler(emu, address, value, size):
    if address >= emu.code_base and address < emu.data_base:
        if emu.unpacker == False:
            if DEBUG > 1:
                print "Writing on top of code at 0x%08x" % emu.cpu.EIP
                print "First address affected 0x%08x" % address

            # Piggyback the modified address space into the emulator
            emu.unpacker_entry = address
            emu.unpacker_end = address
            emu.unpacker = True

        elif emu.unpacker == True:
            if address > emu.unpacker_end:
                emu.unpacker_end = address
            if address < emu.unpacker_entry:
                emu.unpacker_entry = address

        emu.set_pc_handler(address, pc_exit_handler)

    return True

"""
Run the executable in an emulator and to see if it contains the suspicious
string.
"""
@timing
def scan(exe):
    hashes = HashCache()
    exehash = hashfile(exe)
    cache = hashes.check_hash(exehash)

    if cache == True:
        print "The file %s is infected! (cached)" % exe
        return False 
    elif cache == False:
        print "The file %s seems safe. (cached)" % exe
        return True

    emu = PEPyEmu()
    emu.load(exe)
    emu.set_memory_write_handler(code_base_write_handler)
    
    emu.cpu.EIP = emu.entry_point

    # Piggyback a variable into the emulator
    emu.unpacker = False

    while(emu.execute()):
        if DEBUG > 3:
            print "0x%08x" % emu.cpu.EIP

    if DEBUG > 0:
        print "Execution stopped at 0x%08x" % emu.cpu.EIP
    
    if DEBUG > 1:
        if emu.unpacker:
            print "Unpacker started at:  0x%08x" % emu.unpacker_entry
            print "Unpacker finished at: 0x%08x" % emu.unpacker_end

    check_memory = emu.get_memory(emu.unpacker_entry, emu.unpacker_end-emu.unpacker_entry)

    if DEBUG > 2:
        print check_memory

    if "You must detect this file." in check_memory:
        print "The file %s is infected!" % exe
        hashes.add_hash(exehash, True)
        return False
    else:
        print "The file %s seems safe." % exe
        hashes.add_hash(exehash, False)
        return True

if __name__ == "__main__":
    filelist = [
                   r"samples\bad1.exe",
                   r"samples\bad2.exe",
                   r"samples\bad3.exe",
                   r"samples\bad4.exe",
                   r"samples\bad5.exe",
                   r"samples\good1.exe",
                   r"samples\good2.exe",
                   r"samples\good3.exe",
                   r"samples\good4.exe",
                   r"samples\good5.exe",
               ]

    for f in filelist:
        scan(f)
