#!/bin/python3

import os
import time
import datetime
import random

# ============================================================================ #
#                                  CONSTANTS                                   #
# ============================================================================ #

# ChipWhisperer's constants
CRYPTO_TARGET='SIKE'
SCOPETYPE='OPENADC'
PLATFORM='CWLITEARM'

# Instances of SIKE
from collections import namedtuple

Instance = namedtuple("Instance", "prime_bits keylen_bytes sklen_bits sklen_bytes msg_bytes pklen_bytes trace_start trace_end timeout")

"""
NOTE: Alice's public key (pklen_bytes) consists of:
 - 6*N bits that correspond to two coordinates of three elliptic curve points:
     (R[0]->x, R[0]->z, R[1]->x, R[1]->z, R[2]->x, R[2]->z)
 - a hashed message (resp. 128, 192, 192, or 512 bits)

where N = (n-1+7)/8 and n is in {434, 503, 610, 751}.
"""

SIKE_INSTANCES = {
    # SIKEp434 metrics
    434: Instance(prime_bits=434,
                  keylen_bytes=374,
                  sklen_bits=218,
                  sklen_bytes=28,
                  msg_bytes=16,
                  pklen_bytes=346,
                  trace_start=0,
                  trace_end=2500,
                  timeout=0.5),
    # SIKEp503 metrics
    503: Instance(prime_bits=503,
                  keylen_bytes=434,
                  sklen_bits=253,
                  sklen_bytes=32,
                  msg_bytes=24,
                  pklen_bytes=402,
                  trace_start=0,
                  trace_end=2850,
                  timeout=0.5),
    # SIKEp610 metrics
    610: Instance(prime_bits=610,
                  keylen_bytes=524,
                  sklen_bits=305,
                  sklen_bytes=38,
                  msg_bytes=24,
                  pklen_bytes=486,
                  trace_start=0,
                  trace_end=3450,
                  timeout=1),
    # SIKEp751 metrics
    751: Instance(prime_bits=751,
                  keylen_bytes=644,
                  sklen_bits=379,
                  sklen_bytes=48,
                  msg_bytes=32,
                  pklen_bytes=596,
                  trace_start=0,
                  trace_end=4150,
                  timeout=1),
}

# Data path names
DATA_ROOT = os.path.join("data", "p{:03d}")
ALICE_FILENAME = os.path.join("alice_pks", "alice_pk_{:05d}.bin")
BOB_FILENAME = os.path.join("bob_sks", "bob_sk_{:05d}.bin")
TRACES_FILENAME = os.path.join("traces", "traces_{:05d}.txt")

# Python's starting seed for calls to "random"
PYTHON_SEED = "She howls harder than the wind can blow"
random.seed(PYTHON_SEED)

# ============================================================================ #
#                              UTILITY FUNCTIONS                               #
# ============================================================================ #

def log_info(info, f_log=None, end="\n"):
    """
    Log information both on stdout and in logfile.

    @input info  The information to log (String)
    @input f_log Logfile handler to write in
    @input end   End character (as with print)
    """
    print(info, end=end)
    if f_log:
        f_log.write(info + end)

def simpleserial_logsend(target, cmd, payload, timeout=1, preamble="", f_log=None):
    """
    Send command with payload to target and log sending/receiving.

    @input target   ChipWhisperer's target
    @input cmd      Command to send (single ascii)
    @input payload  Command's payload
    @input timeout  Sleep duration before reading (in seconds)
    @input preamble Short string to logged things
    @input f_log    Logfile handler to write in
    @output out     Board's response
    """
    # Log sending
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} {preamble}\tsending \'{cmd}\'... {payload.hex()} (len={len(payload)})", f_log=f_log)

    # Send command
    target.simpleserial_write(cmd, payload)
    time.sleep(timeout)
    while target.in_waiting() == 0:
        time.sleep(timeout)

    # Receive response
    out = target.read(timeout=timeout)
    out_hex = ''.join([hex(ord(i))[2:].zfill(2) for i in out])

    # Log receiving
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} {preamble}\treceiving ... {out_hex} (len={len(out)})", f_log=f_log)

    # Clear buffer (if any)
    target.flush()

    return out

def fileread_bytes(filepath, expected_len):
    """
    Read entire file in bytes and return content.

    @input filepath     Path to file
    @input expected_len Expected number of bytes to read (sanity check)
    @output content     Entire file content
    """
    assert os.path.isfile(filepath), f"File does not exist: {filepath}"
    with open(filepath, "rb") as f:
        content = f.read()
    assert len(content) == expected_len, f"Unexpected number of bytes read in {filepath}: {len(content)} != {expected_len}"
    return content

# ============================================================================ #
#                                    SETUP                                     #
# ============================================================================ #

import chipwhisperer as cw

def chipwhisperersetup(fw_path="", CRYPTO_TARGET='AES', SCOPETYPE='OPENADC', PLATFORM='CWLITEARM'):
    """
    Set up the ChipWhisperer.
    """
    if fw_path == "":
        fw_path = "simpleserial-sike-{}.hex".format(PLATFORM)

    # Try to connect to chipwhisperer
    try:
        scope = cw.scope()
        target = cw.target(scope)
    except IOError:
        print("INFO: Caught exception on reconnecting to target - attempting to reconnect to scope first.")
        print("INFO: This is a work-around when USB has died without Python knowing. Ignore errors above this line.")
        scope = cw.scope()
        target = cw.target(scope)

    print("INFO: Found ChipWhisperer😍")

    if "STM" in PLATFORM or PLATFORM == "CWLITEARM" or PLATFORM == "CWNANO":
        prog = cw.programmers.STM32FProgrammer
    elif PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        prog = cw.programmers.XMEGAProgrammer
    else:
        prog = None

    time.sleep(0.05)
    scope.default_setup()

    # Flash code on card
    cw.program_target(scope, prog, fw_path)

    # The maximum number of samples is hardware-dependent: - cwlite: 24400 - cw1200: 96000
    # Note: can be reconfigured afterwards
    if PLATFORM == "CWNANO":
        scope.adc.samples = 800
    else:
        scope.adc.samples = 2000

    # Prints whatever card sends
    print(target.read())

    return (target, scope)

# ============================================================================ #
#                                   CAPTURE                                    #
# ============================================================================ #

import numpy as np

def CW_campaign(instance, target, scope, idx, N=1, f_log=None, capture=True):
    """
    Run the traces acquisition campaign of the swap_poins procedure for SIKE-p434.

    @input instance Instance of SIKE (must be from SIKE_INSTANCES)
    @input target   ChipWhisperer's target
    @input scope    ChipWhisperer's scope
    @input idx      Current experiment index
    @input N        Total number of experiments
    @input f_log    Logfile handler to write in
    @input capture  Enables the capture from the scope
    """
    exp_plaintexts = []
    exp_keys = []
    exp_swaplabels = []
    exp_traces = []

    # Total number of samples (max. 24400)
    scope.adc.samples = min(instance.trace_end, 24400)

    # Read Alice's entire public key from file
    root = DATA_ROOT.format(instance.prime_bits)
    alice_file = os.path.join(root, ALICE_FILENAME.format(idx))
    pt = fileread_bytes(alice_file, instance.pklen_bytes)

    # Read Bob's entire private key from file, but only consider scalar
    bob_file = os.path.join(root, BOB_FILENAME.format(idx))
    sk = fileread_bytes(bob_file, instance.keylen_bytes)[instance.msg_bytes:instance.msg_bytes+instance.sklen_bytes]
    assert len(sk) == instance.sklen_bytes, f"Unexpected number of bytes for scalar in sk: {len(sk)} != {instance.sklen_bytes}"

    # Generate random seed
    seed = bytearray(random.getrandbits(8) for _ in range(16))

    # Program key and seed, then send Alice's public key
    simpleserial_logsend(target, 'k', sk, preamble=f"({idx+1:05d}/{N:05d})", f_log=f_log)
    simpleserial_logsend(target, 's', seed, preamble=f"({idx+1:05d}/{N:05d})", f_log=f_log)
    simpleserial_logsend(target, 'p', pt, preamble=f"({idx+1:05d}/{N:05d})", f_log=f_log)

    ### RANGE OVER ALL LADDER3PT ITERATIONS ###
    labels = "" # swap bits (i.e., the correct labels)
    traces = [] if capture else None
    for b in range(instance.sklen_bits):
        # Arm oscilloscope
        if capture:
            scope.arm()
        target.flush()

        # Run next loop iteration
        out = simpleserial_logsend(target, 'n', b"", timeout=instance.timeout, preamble=f"({idx+1:05d}/{N:05d}:{b+1:03d}/{instance.sklen_bits:03d})", f_log=f_log)

        # Capture trace
        if capture:
            ret = scope.capture()
            if ret:
                raise Exception('Timeout happened during acquisition')

            # Save trace
            tr = scope.get_last_trace()[instance.trace_start:instance.trace_end]
            traces += [tr]

        # Save label (swapped = b'\x01', untouched = b'\x00')
        labels += out[2]

    return (pt, sk, labels, traces)

# ============================================================================ #
#                                   ATTACK                                     #
# ============================================================================ #

from sklearn.cluster import KMeans
from statistics import mean, variance

# Struct for k-means result
ClusteringResult = namedtuple("ClusteringResult", "time idx labels mins maxs means vars")

class TimingLocationMetrics:
    def __init__(self, result):
        self.results = [result]
        self.occurrences = 1

    def __update__(self, result):
        """
        Deprecated, not used anymore due to completely overlapping minimiums and
        maximums.
        """
        self.mins[0] = min(self.mins[0], result.mins[0])
        self.mins[1] = min(self.mins[1], result.mins[1])
        self.maxs[0] = max(self.maxs[0], result.maxs[0])
        self.maxs[1] = max(self.maxs[1], result.maxs[1])
        self.centers[0] = (self.centers[0] + result.centers[0])/2.0
        self.centers[1] = (self.centers[1] + result.centers[1])/2.0
        self.occurrences += 1

    def append(self, result):
        """
        Appends result to currently saved results.
        """
        self.results += [result]
        self.occurrences += 1

    def __to_string__(self, N):
        """
        Deprecated, was used with the update function.
        """
        return f"Occurrences = {self.occurrences}/{N} ({(100.0*self.occurrences)/N:.2f}%)\n" + f"\tL=0: [{self.mins[0]}, {self.maxs[0]}], mean={self.centers[0]}\n" +  f"\tL=1: [{self.mins[1]}, {self.maxs[1]}], mean={self.centers[1]}"

    def to_string(self, N):
        """
        Format instance to string.
        """
        string = f"Occurrences = {self.occurrences}/{N} ({(100.0*self.occurrences)/N:.2f}%)\n"
        for r in self.results:
            string += f"\ti = {r.idx}: [{r.mins[0]:.10f}, {r.maxs[0]:.10f}] (mu={r.means[0]:.10f}, sig^2={r.vars[0]:.10f}) vs [{r.mins[1]:.10f}, {r.maxs[1]:.10f}] (mu={r.means[1]:.10f}, sig^2={r.vars[1]:.10f})\n"
        return string

    def __lt__(self, other):
        """
        Redefines "less than" operation by comparing number of occurrences.
        """
        return self.occurrences < other.occurrences

def kmeans_clustering(traces, idx):
    """
    Unsupervised K-means clustering of distributions of samples at same timing
    instant.

    @input traces Power traces
    @input idx    Experiment index
    """
    N = len(traces)     # Number of bits
    M = len(traces[0])  # Number of samples
    for t in traces:
        assert len(t) == M, f"Uneven number of samples in traces ({len(t)} != {M})."

    result = []
    for i in range(M):
        distr = np.array([t[i] for t in traces]).reshape(-1,1)
        kmeans = KMeans(n_clusters=2, random_state=0).fit(distr)

        # Sort by mean (lowest mean is label zero)
        if kmeans.cluster_centers_[0] > kmeans.cluster_centers_[1]:
            shift = 1
        else:
            shift = 0

        # Group by labels
        groups = {0:[], 1:[]}
        for j in range(N):
            groups[shift ^ kmeans.labels_[j]] += [traces[j][i]]

        # Create cluster result and store it
        result += [ClusteringResult(time=i,
                                    idx=idx,
                                    labels=''.join([str(l) for l in kmeans.labels_]),
                                    mins={0: min(groups[0]), 1: min(groups[1])},
                                    maxs={0: max(groups[0]), 1: max(groups[1])},
                                    means={0: mean(groups[0]), 1: mean(groups[1])},
                                    vars={0: variance(groups[0]), 1: variance(groups[1])},)]
    return result

def attack(labels, traces, idx, successful_times, N=1, f_log=None):
    """
    Performs the overall attack that consits of:
        (1) Select a sample location
        (2) Clustering the sample distributions at said location with K-means
        (3) Determine if the correct key could be recovered
    """
    log_info(f"Starting the attack ...", f_log=f_log)
    successes = 0

    # Inverse of labels, in case clustering swapped 0 <-> 1
    inv_labels = ''.join([str(1-int(l)) for l in labels])

    # Clutering with K-means
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} ({idx+1:05d}/{N:05d}): Clustering with K-means...", f_log=f_log)
    log_info(f"{now} ({idx+1:05d}/{N:05d}): Key={labels}\n", f_log=f_log)
    result = kmeans_clustering(traces, idx)

    # Count the occurrences
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} ({idx+1:05d}/{N:05d}): Analyzing results... ", f_log=f_log, end="")
    occurrences = []
    for c in result:
        if c.labels == labels or c.labels == inv_labels:
            occurrences += [c]

    # Report success or failure
    if len(occurrences) > 0:
        log_info(f"Success!", f_log=f_log, end="\n\n")
        successes += 1
        for o in occurrences:
            if o.time in successful_times:
                successful_times[o.time].append(o)
            else:
                successful_times[o.time] = TimingLocationMetrics(o)
    else:
        log_info(f"FAILURE!!!", f_log=f_log, end="\n\n")

def SIKEswap_capture(instance, target, scope, idx, successful_times, N, f_log=None, capture=True):
    # Preamble
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    log_info(f"{now} ({idx+1:05d}/{N:05d}): Launching acquisition", f_log=f_log)

    # Acquire and plot traces
    (_, _, labels, traces) = CW_campaign(instance, target, scope, idx, N=N, f_log=f_log, capture=capture)

    # Run the attack
    if traces:
        attack(labels, traces, idx, successful_times, N=N, f_log=f_log)

def SIKEswap_kmeans_experiment(sikep, N=1, rg=None, logged=False, capture=True):
    """
    Derive success probability of the K-means clustering by launching N
    experiments.
    """
    # Open log file
    f_log = None
    target = None
    scope = None
    successful_times = {}

    if rg == None:
        rg = range(N)
    instance = SIKE_INSTANCES[sikep]
    if logged:
        logfilename = datetime.datetime.now().strftime(f"log/%Y-%m-%d_%H-%M-%S_SIKEp{sikep}-swap.txt")
        f_log = open(logfilename, 'w')
        print(f"Opened {logfilename} !")

    try:
        # Start experimentation
        log_info(f"SIKE-p{sikep} campaign launched", f_log=f_log)
        log_info(f"N: {N}", f_log=f_log)
        log_info(f"Range: {rg}", f_log=f_log)
        log_info(f"N_bits: {instance.sklen_bits}", f_log=f_log)
        log_info(f"="*80, f_log=f_log)

        # Open ChipWhisperer's target and scope
        fw_path = f"/home/lemonade/Code/chipwhisperer-5.2.1/hardware/victims/firmware/simpleserial-sike-p{sikep}/simpleserial-sike-p{sikep}-{PLATFORM}.hex"
        (target, scope) = chipwhisperersetup(fw_path=fw_path)

        ### LAUNCH CAMPAIGN ###
        for idx in rg:
            SIKEswap_capture(instance, target, scope, idx, successful_times, N, f_log=f_log, capture=capture)

    finally:
        # Print successful times
        for s, t in sorted(((v,k) for k,v in successful_times.items()), reverse=True) :
            log_info(f"Time: {t} " + s.to_string(N), f_log=f_log)
        if f_log:
            print(f"Closing {logfilename}...")
            f_log.close()
        if target:
            print(f"Closing target")
            target.dis()
        if scope:
            print(f"Closing scope")
            scope.dis()

# ============================================================================ #
#                                    MAIN                                      #
# ============================================================================ #

import argparse
import re

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch end-to-end clustering power analysis attack on ChipWhisperer')
    parser.add_argument('-p', nargs='?', type=int, help="SIKE instance prime size (434, 503, 610, 751)", default=434)
    parser.add_argument('-N', nargs='?', type=str, help="N experiments (or range x:y)", default="2")
    parser.add_argument('-l', help="DO NOT log analysis in file", action='store_false')
    parser.add_argument('-c', help="Capture traces from the ChipWhisperer", action='store_true')
    args = parser.parse_args()
    if args.p in SIKE_INSTANCES:
        p = re.compile(r"([0-9]+):?([0-9]+)?")
        m = p.match(args.N)
        if m:
            low = int(m.groups()[0])
            hi  = low if m.groups()[1] == None else int(m.groups()[1])
        else:
            low = 0
            hi = 2

        rg = None
        if hi == low:
            rg = range(int(hi))
        elif hi > low:
            rg = range(int(low), int(hi))
        else:
            print(f"Error: range({low}, {hi}) is not valid!")

        if rg != None:
            SIKEswap_kmeans_experiment(sikep=args.p, N=hi, rg=rg, logged=args.l, capture=args.c)
    else:
        print(f"Error: SIKEp{args.p} does not exist!");
