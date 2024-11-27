#include <stdio.h>
#include <stdlib.h>
#include "/usr/local/include/pbc/pbc.h"

extern int g1_len, gt_len, zr_len;

int ld_param(FILE *fp, element_t g, element_t pk, element_t sk, element_t gsk, element_t pk2, element_t sk2, mpz_t N, mpz_t pi, mpz_t e, mpz_t d) {
    //加载提前存好的公私钥
    unsigned char g1_buf[g1_len], zr_buf[zr_len];

    fread(g1_buf, g1_len, 1, fp);
    element_from_bytes_compressed(g, g1_buf);

    fread(g1_buf, g1_len, 1, fp);
    element_from_bytes_compressed(pk, g1_buf);

    fread(zr_buf, zr_len, 1, fp);
    element_from_bytes(sk, zr_buf);

    fread(g1_buf, g1_len, 1, fp);
    element_from_bytes_compressed(gsk, g1_buf);

    fread(g1_buf, g1_len, 1, fp);
    element_from_bytes_compressed(pk2, g1_buf);

    fread(zr_buf, zr_len, 1, fp);
    element_from_bytes(sk2, zr_buf);

    mpz_inp_raw(N, fp);
    mpz_inp_raw(pi, fp);
    mpz_inp_raw(e, fp);
    mpz_inp_raw(d, fp);

    return 0;
}
