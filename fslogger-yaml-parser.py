import yaml as y
import pprint as pp
import os, sys

# Return all processes
def get_processes(data):
    processes = {}
    for doc in data:
        pid   = doc['Event']['pid']
        pname = doc['Event']['pname']
        # Create dictionary of PIDs and process names
        if pid in processes.keys():
            if pname not in processes[pid]: processes[pid].append(pname)
        else:
            processes[pid] = []
            processes[pid].append(pname)
    return processes

# Return all process files
def get_process_files(data):
    processes = {}
    strings   = ['FSE_ARG_STRING_0','FSE_ARG_STRING_1']
    # {pid:{pname:[file0,file1]}}
    for doc in data:
        pid   = doc['Event']['pid']
        pname = doc['Event']['pname']
        # Create dictionary of PIDs and process names
        if pid in processes.keys():
            if pname not in processes[pid].keys(): processes[pid][pname] = []
        else:
            processes[pid] = {}
            processes[pid][pname] = []
        for e in strings:
            if doc['Details'].has_key(e):
                if doc['Details'][e]['string'] not in processes[pid][pname]:
                    processes[pid][pname].append(doc['Details'][e]['string'])

    return processes

# Return all process files
def get_process_files2(data):
    processes = {}
    strings   = ['FSE_ARG_STRING_0','FSE_ARG_STRING_1']
    padding   = len('FSE_CONTENT_MODIFIED')
    # {pid:{pname:[file0,file1]}}
    for doc in data:
        pid   = doc['Event']['pid']
        pname = doc['Event']['pname']
        # Create dictionary of PIDs and process names
        if pid in processes.keys():
            if pname not in processes[pid].keys(): processes[pid][pname] = []
        else:
            processes[pid] = {}
            processes[pid][pname] = []
        for e in strings:
            if doc['Details'].has_key(e):
                #sn = doc['Event']['type'] + ": " + doc['Details'][e]['string']    
                sn = "%s: %s" % (doc['Event']['type'].ljust(padding), doc['Details'][e]['string'])
                #if doc['Details'][e]['string'] not in processes[pid][pname]:
                    #processes[pid][pname].append(doc['Details'][e]['string'])
                if sn not in processes[pid][pname]:
                    processes[pid][pname].append(sn)

    return processes

# Return unique pids
def get_pids(data):
    pids = []
    for doc in data:
        pids.append(doc['Event']['pid'])
    pids = set(pids)
    pids = list(pids)
    return pids

# Return unique pnames
def get_pnames(data):
    pnames = []
    for doc in data:
        pnames.append(doc['Event']['pname'])
    pnames = set(pnames)
    pnames = list(pnames)
    return pnames

# Return unique filenames
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

    
def list_processes(data):
    processes = get_processes(y.load_all(data))
    print "Detected Processes:"
    #print processes
    for e in processes.keys():
        print "    " + str(e) + ":",
        print ','.join(processes[e])
            
def list_process_files(data):
    print "Detect Processes and Files"
    print 
    #processes = get_process_files(y.load_all(data))
    processes = get_process_files2(y.load_all(data))
    for pid in processes.keys():
        print str(pid) + ":"
        for pname in processes[pid].keys():
            print "    " + pname
            for fn in processes[pid][pname]:
                print "        " + fn


# Help
def usage():
    print "fslogger-yaml-parser.py:  This script will take YAML output of fslogger data" 
    print "                          and parse it for various information."
    print ""
    print "-f <file>:       Input file (required)"
    print "-p:              Print process identifier numbers and a list of corresponding process names."
    print "-n:              Print process identifier and then list the files associated with each process name."
    print "-h:              Print help."
    sys.exit()

if __name__ == "__main__":

    # Variables
    inf             = ""
    print_pids      = False;
    print_files     = False;

    # Process Options
    ops = ['-f','-p','-n','-h']

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-f':
            inf = sys.argv.pop(1)
        if op == '-p':
            print_pids  = True
        if op == '-n':
            print_files = True
        if op == '-h':
            usage()
        if op not in ops:
            print "Unknown option:"
            usage()

    # Check for file
    if not inf:
        usage()

    # Import and open data file
    # Do not readlines as we need a full dump
    d = open(inf,'r').read()

    # Load YAML dataspace
    # Cannot make an object because it is a generator and it cannot be reset
    # Example: yd = y.load_all(d)

    # Process Data
    # Error Check
    err_check = []
    err_check = fix_int64_errors(d)
    if err_check[0]:
        # Error was detected and, hopefully, fixed
        print "Error detected, data modified to compensate."
        d = err_check[1]
    
    if print_pids: list_processes(d)
    if print_files: list_process_files(d)
