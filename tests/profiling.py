#!/usr/bin/python3
#
# Quick script used to run the profiling build from the 'make' system.
#
#


import os, sys, re, subprocess


myfullpath = os.path.dirname( os.path.realpath(__file__) )

count = 2000
if len( sys.argv ) > 0:
    try:
        count = int( sys.argv[1] )
    except:
        pass


print( "===== RUNNING PROFILING (" + str(count) + " outputs) =====" )
print( "\tGetting binary symbol table" )
getsym = [ "objdump", "-t", myfullpath+"/../bin/nanofuzz" ]
sym = subprocess.Popen( getsym, stdout=subprocess.PIPE )

symbols = {}
for line in sym.stdout.readlines():
    x = [ p.strip() for p in re.split( " +", line.decode("utf-8") ) ]
    if len(x) < 2 or len(x[-1]) < 1 or len(x[0]) < 1:
        continue

    _offset = re.sub( '^0+|[^0-9a-f]*$', '', str(x[0]) )
    if len(_offset) < 1:
        continue

    offset = "0x" + _offset
    func = x[-1]

    _obj = {"name":func}
    symbols[offset] = _obj


execall = [ myfullpath+"/../bin/nanofuzz", "-l", str(count), "-f", myfullpath+"/compliance/simple_mixed1.txt" ]
print( "\tExecuting nanofuzz" )
proc = subprocess.Popen( execall, stdout=subprocess.PIPE )

for line in proc.stdout.readlines():
    x = [ p.strip().replace('|', '') for p in line.decode("utf-8").split("-->") ]
    if len(x) < 3:
        continue

    addr = x[0]
    time = x[1]
    amnt = x[2]

    if addr in symbols.keys():
        symbols[addr]["time"] = time
        symbols[addr]["amnt"] = amnt
    else:
        print( "\t\tMisunderstood function pointer; no equivalent symbol for '"
            + addr +"', called " + str(amnt) + " times." )


# Remove symbols from the list that weren't executed in the profiling call.
print( "\tCleaning unrelated symbols" )
pops = []
for x in symbols.keys():
    if not "time" in symbols[x].keys():
        pops.append(x)

for x in pops:
    symbols.pop(x)

# Sort the result.
symbols_sorted = sorted( symbols.values(), key=lambda x: x["time"] )
symbols_sorted.reverse()

# Finally, print all timed information.
print( "\n\n| {:<48} | {:<16} | {:<16} |".format('FUNCTION','TIME','CALLS') )
for y in symbols_sorted:
    try:
        if float( y["time"].replace('s','') ) < 0.0001:
            continue
    except:
        pass

    print( "| {:<48} | {:<16} | {:<16} |".format( y["name"], y["time"], y["amnt"] ) )


print( "\n\n" )
