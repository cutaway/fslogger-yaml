import yaml as y
import pprint as pp
import os, sys

# Return all pids
def get_pids(data):
    pids = []
    for doc in data:
        pids.append(doc['Event']['pid'])
    return pids

# Return all pnames
def get_pnames(data):
    pnames = []
    for doc in data:
        pnames.append(doc['Event']['pname'])
    return pnames

# Return all filenames
def get_filenames(data):
    files = []
    for doc in y.load_all(d):
        files.append(doc['Details']['FSE_ARG_STRING']['string'])
    return files


if __name__ == "__main__":

    # Import and open data file
    inf = sys.argv[1]
    # Do not readlines as we need a full dump
    d = open(inf,'r').read()

    # Load YAML dataspace
    # Cannot make an object because it is a generator and it cannot be reset
    #yd = y.load_all(d)

    # Process Data
    print "PIDs detected:"
    for e in get_pids(y.load_all(d)):
        print "   ",e
    print ""

    print "Process names detected:"
    for e in get_pnames(y.load_all(d)):
        print "   ",e
    print ""

    print "Files names detected:"
    for e in get_filenames(y.load_all(d)):
        print "   ",e
    print ""

