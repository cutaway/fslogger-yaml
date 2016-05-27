import yaml as y
import pprint as pp
import os, sys

# Return all pids
def get_pids(data):
    pids = []
    for doc in data:
        pids.append(doc['Event']['pid'])
    pids = set(pids)
    pids = list(pids)
    return pids

# Return all pnames
def get_pnames(data):
    pnames = []
    for doc in data:
        pnames.append(doc['Event']['pname'])
    pnames = set(pnames)
    pnames = list(pnames)
    return pnames

# Return all filenames
def get_filenames(data):
    files = []
    #for doc in y.load_all(d):
    for doc in data:
        files.append(doc['Details']['FSE_ARG_STRING']['string'])
    files = set(files)
    files = list(files)
    return files

# Fix FSE_ARG_INT64 Errors
def fix_int64_errors(data):

    found        = 0
    new_data     = ""
    fix_int64    = [' FSE_ARG_INT64:','  len: -1','  tstamp: -1',' FSE_ARG_DONE:','  len: 0','  type: 45887']
    int64_errors = [' FSE_ARG_INT64# => received',' FSE_ARG_INT64---']

    # Split on newlines to generate a list of data
    dl = data.split('\n')

    # Loop through looking for typical errors
    for e in range(len(dl)):
        for int64_err in int64_errors:
            if int64_err in dl[e]:
                # Count errors
                found += 1
                print("Error detected in line %s: %s",e,dl[e])
                print "Updating error with marked modifications. Look for -1 values in FSE_ARG_INT64 values."
                # Set up follow-up line by stripping original element
                tmp = dl[e].replace(" FSE_ARG_INT64","")
                # Fix data with data that shows an error
                for i in range(len(fix_int64)):
                    # Replace the original line
                    if not i: 
                        dl[e] = fix_int64[i]
                        continue
                    # Add marked updates
                    dl.insert(e+i,fix_int64[i])
                # Add follow-up line
                dl.insert(e+i+1,tmp)

    if found:
        # Found errors, pull data back together to make glob
        for e in dl:
            new_data += e + '\n'

    return [found,new_data]


if __name__ == "__main__":

    # Import and open data file
    inf = sys.argv[1]
    # Do not readlines as we need a full dump
    d = open(inf,'r').read()

    # Load YAML dataspace
    # Cannot make an object because it is a generator and it cannot be reset
    #yd = y.load_all(d)

    # Process Data
    try:
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
    except:
        err_check = []
        err_check = fix_int64_errors(d)
        if err_check[0]:
            d = err_check[1]
        else:
            print "Unknown errors.\n"
            sys.exit(1)

        print "Errors detected and fixed:",err_check[0]
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

