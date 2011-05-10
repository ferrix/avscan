from __future__ import with_statement
import hashlib
from functools import wraps
import os
import sys
import cPickle
import pefile
sys.path.append(r'C:\pyemu')
sys.path.append(r'C:\pyemu\lib')

DEBUG=0

if 'SCANNER_DEBUG' in os.environ.keys():
    DEBUG = int(os.environ['SCANNER_DEBUG'])

try:
    import PyEmu, PyOS
except:
    print "PyEmu not found"
    sys.exit(1)
import time

class UnpackerPyEmu(PyEmu.PEPyEmu):
    unpacker = False
    unpacker_entry = 0
    unpacker_end = 0

class PyFakeWindows(PyOS.PyWindows):
    def add_library(self, dll, function):
	#self.libraries[0x00400000] = {'address': 0x00400000, 'name': function}
	return True

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
        if DEBUG > 0:
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

def unpacker(exe, identifier):
    pe = pefile.PE(exe)

    packed = False
    
    for section in pe.sections:
        if getattr(section, 'IMAGE_SCN_MEM_WRITE') and getattr(section, 'IMAGE_SCN_MEM_EXECUTE'):
            packed = True

    if not packed:
        return False

    emu = UnpackerPyEmu()
    emu.os = PyFakeWindows()
    emu.setup_os()
    emu.load(exe)
    emu.set_memory_write_handler(code_base_write_handler)
    
    emu.cpu.EIP = emu.entry_point

    # Piggyback a variable into the emulator
    emu.unpacker = False

    while(emu.execute()):
        if DEBUG > 4:
            print "0x%08x" % emu.cpu.EIP

    if DEBUG > 1:
        print "Execution stopped at 0x%08x" % emu.cpu.EIP
    
    if DEBUG > 2:
        if emu.unpacker:
            print "Unpacker started at:  0x%08x" % emu.unpacker_entry
            print "Unpacker finished at: 0x%08x" % emu.unpacker_end

    check_memory = emu.get_memory(emu.unpacker_entry, emu.unpacker_end-emu.unpacker_entry)

    if DEBUG > 3:
        print check_memory

    if identifier in check_memory:
        return True
    else:
        return False

def matcher(exe, identifier):
    b1 = ""
    with file(exe, 'rb') as f:
        while True:
            b2 = f.read(4096)
            if not b2:
                return False
            if identifier in b1+b2:
                return True

scans = [
            ("matcher", matcher),
            ("unpacker", unpacker),
           ]

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
        return True 
    elif cache == False:
        print "The file %s seems safe. (cached)" % exe
        return False

    identifier = "You must detect this file."

    for (name, func) in scans:
        result = func(exe, identifier)
        
        if result == True:
            print "The file %s is infected! (%s)" % exe, name
            hashes.add_hash(exehash, True)
            return True
    
    print "The file %s seems safe." % exe
    hashes.add_hash(exehash, False)
    return False

if __name__ == "__main__":
    filelist = []
    for filename in sys.argv[1:]:
        filelist.append(filename)

    if not len(filelist):
	print "Usage: %s files" % sys.argv[0]
        sys.exit(1)

    for f in filelist:
        scan(f)
