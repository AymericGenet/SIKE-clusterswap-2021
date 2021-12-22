# SIKE Clustering Power Analysis

Supplementary material of the submission of *Single-trace clustering power analysis of the point-swapping procedure in the three point ladder of Cortex-M4 SIKE* to COSADE 2022.

## Details

Material included in this repository
* [`chipwhisperer`](chipwhisperer/): Attacked source code that was flashed to STM32.
* [`data`](data/): Ciphertexts and secret keys considered in the attack, and example of segmented traces.
* [`logs`](logs/): Logs output of acquisition and experiments.
* [`PQCrypto-SIDH`](PQCrypto-SIDH/): Implementation used to generate ciphertexts and secret keys.
* [`scripts`](scripts/): Scripts used to acquire the power traces and to perform the attack.