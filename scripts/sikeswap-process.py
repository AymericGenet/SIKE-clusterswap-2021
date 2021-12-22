SAMPLING_RATE = 2.5E8

def thresholding_2pop(distr, iterations=1):
    """
    Clusters the distributions in two populations based on thresholding with the
    middle point: (min+max)/2.

    @input distr      The overall distribution of power samples at a same timing
                      location that will be split into two clusters.
    @input iteration  The number of iterations in an educated thresholding.
    @output A list of the labels of each sample in distr (one per iteration).
    """

    # Number of bits
    N = len(distr)
    labels = []
    midpoint = N//2

    # Sort by sample values
    distr.sort(key=lambda pair: pair[1])

    # Find midpoint
    midvalue = (distr[-1][1] + distr[0][1])/2
    midpoint = np.searchsorted([v for (_, v) in distr], midvalue, side="left")

    # Find threshold
    shift = 0
    for i in range(iterations):
        if i == 0:
            # First threshold is simply the midpoint
            threshold = midpoint
            clusters = (distr[:threshold], distr[threshold:])
            means = (mean([s for (s, _) in clusters[0]]), mean([s for (s, _) in clusters[1]]))
        else:
            # Further iteration move the threshold depending on distance with means of current clusters
            means = (mean([s for (s, _) in clusters[0]]), mean([s for (s, _) in clusters[1]]))

            # Shift threshold depending on distance with means
            shift += 1 if (midpoint + shift < N) and (midpoint - shift >= 0) else 0
            sample = distr[threshold][1]
            if (sample - means[0])**2 < (sample - means[1])**2:
                # Shift to the right
                while (midpoint + shift < N) and (distr[threshold][1] == distr[midpoint+shift][1]):
                    shift += 1
                threshold = midpoint + shift
            else:
                # Shift to the left
                while (midpoint - shift >= 0) and (distr[threshold][1] == distr[midpoint-shift][1]):
                    shift += 1
                threshold = midpoint - shift
            clusters = (distr[:threshold], distr[threshold:])

        # Assign labels
        l = N*['0']
        for (idx, _) in clusters[1]:
            l[idx] = '1'

        # Save labels
        labels += [''.join(l)]

        # Safe break
        if (midpoint + shift >= N) or (midpoint - shift < 0) or len(clusters[0]) == 0 or len(clusters[1]) == 0:
            break

    return labels

def custom_kmeans(distr, dist=lambda x,y: abs(x - y)):
    """
    Clusters the distributions in two populations based on the unsupervised
    k-means clustering algorithm.

    @input distr The overall distribution of power samples at a same timing
                 location that will be split into two clusters.
    @input dist  A function that computes distance (default: |x - y|).
    @output The labels of each sample in distr.
    """

    # Number of bits
    N = len(distr)
    labels = []
    midpoint = N//2

    # Sort by sample values
    distr.sort(key=lambda pair: pair[1])

    # Find midpoint
    midvalue = distr[midpoint][1]
    midpoint = np.searchsorted([v for (_, v) in distr], midvalue, side="left")

    # Assign
    clusters = {0: [p for p in distr[:midpoint]], 1: [p for p in distr[midpoint:]]}
    means = {0: None, 1: None}
    if len(clusters[0]) > 0 and len(clusters[1]) > 0:
        means[0] = mean([s for (_, s) in clusters[0]])
        means[1] = mean([s for (_, s) in clusters[1]])

    prevmeans = [None, None]
    # Check for change of values
    # NOTE: Even though the values are floats, we check for change in cluster
    #       rather than an actual change of value
    while prevmeans[0] != means[0] and prevmeans[1] != means[1]:
        clusters = {0: [], 1:[]}
        for (idx, s) in distr:
            if dist(s, means[0]) < dist(s, means[1]):
                clusters[0] += [(idx, s)]
            else:
                clusters[1] += [(idx, s)]
        prevmeans[0] = means[0]
        prevmeans[1] = means[1]
        if len(clusters[0]) > 0 and len(clusters[1]) > 0:
            means[0] = mean([s for (_, s) in clusters[0]])
            means[1] = mean([s for (_, s) in clusters[1]])

    # Return final labels
    labels = N*['0']
    for (idx, _) in clusters[1]:
        labels[idx] = '1'

    return ''.join(labels)

def validatekey_horizontal_majority(labels):
    """
    Validate key within labels obtained from kmeans clustering with majority
    rule, i.e., the key (or its complement) which appears the most in all
    recovered labels.

    @input labels  The list of all labels obtained by the attack.
    """
    keydict = {}
    for output in labels:
        key = ''.join([str(i) for i in output.labels])
        inv_key = ''.join([str(1-i) for i in output.labels])

        # Collides key with inv_key
        if key in keydict:
            keydict[key] += 1
        elif inv_key in keydict:
            keydict[inv_key] += 1
        else:
            keydict[key] = 1

    # Sort and return results
    return dict(sorted(keydict.items(), key=lambda x: x[1], reverse=True))

def SIKEswap_experiment_results(N=1000, wvrange=range(8), wavelet='sym4', attack=attack_thresh, traces_dir="data/p434/traces", align_params=ALIGN_PARAMS[434]):
    """
    Derive success probability of the K-means clustering by using the traces
    acquired by the oscilloscope.
    """

    logfilename = datetime.datetime.now().strftime("logs/%Y-%m-%d_%H-%M-%S_swap-kmeans-experiment.txt")
    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    print(f"{now}: Start!\n")
    with open(logfilename, 'w') as f:
        try:
            successrate = {}
            fft_successrate = {}
            keys = np.loadtxt(os.path.join(traces_dir, "labels.txt"), dtype="str")
            subdirs = list(filter(lambda x: os.path.isdir(os.path.join(traces_dir, x)), sorted(os.listdir(traces_dir))))
            for wl in wvrange:
                successrate[wl] = None
                fft_successrate[wl] = None
                # For all experiments
                for i in range(N):
                    d = subdirs[i]
                    print(f"{now} [{i+1}/{N}]: Directory={d}")
                    f.write(f"{now} [{i+1}/{N}]: Directory={d}\n")

                    # Collect traces
                    files = list(sorted(os.listdir(os.path.join(traces_dir, d))))
                    traces = []
                    for tr_f in files:
                        traces += [np.loadtxt(os.path.join(traces_dir, d, tr_f))]

                    now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")

                    # Get key
                    key = keys[i]
                    inv_key = ''.join(['0' if c == '1' else '1' for c in key])
                    print(f"{now} [{i+1}/{N}]: Key={key}")
                    f.write(f"{now} [{i+1}/{N}]: Key={key}\n")

                    # Cluster Wavelet domain
                    traces = wavelet_denoise(traces, N=wl, wavelet=wavelet)

                    print(f"{now} [{i+1}/{N}]: Clustering in timing domain ({len(traces[0])})...")
                    f.write(f"{now} [{i+1}/{N}]: Clustering in timing domain ({len(traces[0])})...\n")
                    labels = attack(traces)

                    if successrate[wl] == None:
                        successrate[wl] = len(traces[0])*[0]
                    Nsuccessful = 0
                    for (idx, l) in labels:
                        if key in l or inv_key in l:
                            successrate[wl][idx] += 1
                            Nsuccessful += 1

                    print(f"{now} [{i+1}/{N}]: Found {labels[-1][0]} candidates, {Nsuccessful} successful...")
                    f.write(f"{now} [{i+1}/{N}]: Found {labels[-1][0]} candidates, {Nsuccessful} successful...\n")

                    # Cluster Fourier domain
                    (freqs, traces) = fft_traces(traces, sample_rate=SAMPLING_RATE)

                    print(f"{now} [{i+1}/{N}]: Clustering in frequency domain ({len(traces[0])})...")
                    f.write(f"{now} [{i+1}/{N}]: Clustering in frequency domain ({len(traces[0])})...\n")
                    labels = attack(traces)

                    if fft_successrate[wl] == None:
                        fft_successrate[wl] = len(traces[0])*[0]
                    Nsuccessful = 0
                    for (idx, l) in labels:
                        if key in l or inv_key in l:
                            fft_successrate[wl][idx] += 1
                            Nsuccessful += 1

                    print(f"{now} [{i+1}/{N}]: Found {labels[-1][0]} candidates, {Nsuccessful} successful...")
                    f.write(f"{now} [{i+1}/{N}]: Found {labels[-1][0]} candidates, {Nsuccessful} successful...\n")

        finally:
            now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            for wl in successrate:
                if successrate[wl] != None:
                    np.savetxt(f"logs/SIKE-swap-SR/SR-{wl}.txt", successrate[wl], fmt="%d", delimiter=" ")
            for wl in fft_successrate:
                if fft_successrate[wl] != None:
                    np.savetxt(f"logs/SIKE-swap-SR/SR-fft-{wl}.txt", fft_successrate[wl], fmt="%d", delimiter=" ")
            print(f"\n{now}: The end!")