#include <stdio.h>
#include <string.h>
#include "../src/P503/P503_api.h"
#include "../src/P503/P503_internal.h"

#define N_ALICE_KEYS 10000

static void binwrite_to_file(char* const filename, unsigned char* const bytes, const size_t len) {
    FILE *f = fopen(filename, "wb");
    fwrite(bytes, len, 1, f);
    fclose(f);
}

static void write_keys(const size_t N) {
    int i = 0;
    char filename[128];

    unsigned char ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

    for (i = 0; i < N; ++i) {
        crypto_kem_keypair_SIKEp503(pk, sk);
        crypto_kem_enc_SIKEp503(ct, ss, pk);

        snprintf(filename, 128, "custom/data/p503/bob_sk_%05d.bin", i);
        binwrite_to_file(filename, sk, CRYPTO_SECRETKEYBYTES);

        snprintf(filename, 128, "custom/data/p503/alice_pk_%05d.bin", i);
        binwrite_to_file(filename, ct, CRYPTO_CIPHERTEXTBYTES);
    }

}

int main(void) {
    write_keys(N_ALICE_KEYS);

    return 0;
}
