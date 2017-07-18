import sys

stats_per_core = {}

with open(sys.argv[1], 'r') as f:
    for line in f.readlines():
        fields = line.split()
        if len(fields) < 12:
            continue
        try:
            core = int(fields[1].replace("]",""))
        except ValueError, IndexError:
            continue
        mps = float(fields[6].replace(",",""))
        tp = float(fields[8].replace(",",""))
        cnxs = float(fields[11])
        if core not in stats_per_core:
            stats_per_core[core] = list()
        stats_per_core[core].append({"mps": mps, "tp": tp, "cnxs": cnxs})
        
mps = 0
tp = 0
cnxs = 0
for core in stats_per_core:
    if len(stats_per_core[core]) < 60:
        print "Core {0} does not have at least 60 records".format(core)
        sys.exit(-1)
    mps += sum(x["mps"] for x in stats_per_core[core][-60:])
    tp += sum(x["tp"] for x in stats_per_core[core][-60:])
    cnxs += sum(x["cnxs"] for x in stats_per_core[core][-60:])

mps = mps / 60.0
tp = tp / 60.0
cnxs = cnxs / 60.0

print "M/s: {0:,}\nTp: {1:,}\nCnxs: {2:,}".format(mps, tp, cnxs)
