import hashlib

class hasher(object):
    sha256 = hashlib.sha256()

    """ Check the beginning of the file with two hashes """
    def hashfile(self, path):
	m = hashlib.sha256()
	with file(path) as f:
	    while True:
                d = f.read(8096)
                if not d:
                    break
                m.update(d) 	  
            return m.hexdigest()
