#include "peks.h"
#include "sa_peks.h"
#include "paeks.h"
#include "paeks20.h"
#include "ibgeks.h"
#include "ldparams.h"
#include <sys/time.h>

int g1_len, gt_len, zr_len;
char dataset[1024][64];

static double time_cost(struct timeval A, struct timeval B) {
    double res;
    res = (B.tv_sec - A.tv_sec) * 1000000 + B.tv_usec - A.tv_usec;
    return res / 1000; 
}

int save_cipher(FILE *fp, element_t A, const char * B) {
    //密文存储到文件
    unsigned char g1_buf[g1_len];
    element_to_bytes_compressed(g1_buf, A);
    fwrite(g1_buf, g1_len, 1, fp);
    fwrite(B, HASH_LEN, 1, fp);
    return 0;
}

int save_cipher2(FILE *fp, element_t A, element_t B) {
    //密文存储到文件
    unsigned char g1_buf[g1_len];
    element_to_bytes_compressed(g1_buf, A);
    fwrite(g1_buf, g1_len, 1, fp);
    element_to_bytes_compressed(g1_buf, B);
    fwrite(g1_buf, g1_len, 1, fp);
    return 0;
}

int main(int argc, char * argv[]) {
    
	char * param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    //椭圆曲线type-f BN256
    pairing_t pairing;
    element_t g, pk, sk, gsk, pk2, sk2, Ca, Cb2;
    mpz_t N, pi, e, d;
    int T, sum;
    FILE *fp, *fq, *fw;
    char w[64], Cb[HASH_LEN];
    struct timeval start, end;
    double cost1, cost2, cost3, cost4, cost5;

    // if(argc < 7) {
    //     return 0;
    // }
    fp = fopen("param.txt", "rb");
    fw = fopen("keyword.txt", "r");
    sum = atoi(argv[1]);//测试的数据量
    //初始化pairing
    pairing_init_set_str(pairing, param);
    g1_len = pairing_length_in_bytes_compressed_G1(pairing);
    gt_len = pairing_length_in_bytes_GT(pairing);
    zr_len = pairing_length_in_bytes_Zr(pairing);

    element_init_G1(Ca, pairing);
    element_init_G1(Cb2, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);
    element_init_G1(pk2, pairing);
    element_init_G1(gsk, pairing);
    element_init_Zr(sk, pairing);
    element_init_Zr(sk2, pairing);
    mpz_init(N);
    mpz_init(pi);
    mpz_init(e);
    mpz_init(d);

    ld_param(fp, g, pk, sk, gsk, pk2, sk2, N, pi, e, d);

    for(int i = 0; i < sum; i++) {
        if(fscanf(fw, "%s", w) != EOF) {
            strcpy(dataset[i], w);
        }else {
            printf("Error!\n");
            break;
        }
    }

    fq = fopen("ibgeks_cipher.txt", "wb");
    for(int i = 0; i < sum; i++) {
        ibgeks_encrypt(Ca, Cb, pairing, gsk, dataset[i], "ID0");
        save_cipher(fq, Ca, Cb);
    }
    fclose(fq);

    fq = fopen("peks_cipher.txt", "wb");
    for(int i = 0; i < sum; i++) {
        peks_encrypt(Ca, Cb, pairing, g, pk, dataset[i]);
        save_cipher(fq, Ca, Cb);
    }
    fclose(fq);

    fq = fopen("sa_peks_cipher.txt", "wb");
    for(int i = 0; i < sum; i++) {
        sa_peks_encrypt(Ca, Cb, pairing, g, pk, N, e, d, dataset[i]);
        save_cipher(fq, Ca, Cb);
    }
    fclose(fq);

    fq = fopen("paeks_cipher.txt", "wb");
    for(int i = 0; i < sum; i++) {
        paeks_encrypt(Ca, Cb2, pairing, g, pk, sk2, dataset[i]);
        save_cipher2(fq, Ca, Cb2);
    }
    fclose(fq);

    fq = fopen("paeks20_cipher.txt", "wb");
    for(int i = 0; i < sum; i++) {
        paeks20_encrypt(Ca, Cb, pairing, g, pk, sk2, dataset[i]);
        save_cipher(fq, Ca, Cb);
    }
    fclose(fq);

    cost1 = 0.0;
    cost2 = 0.0;
    cost3 = 0.0;
    cost4 = 0.0;
    cost5 = 0.0;
    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        ibgeks_encrypt(Ca, Cb, pairing, gsk, dataset[i], "ID0");
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost1 += time_cost(start, end);
            printf("%.3f\n", cost1);
            gettimeofday(&start, NULL);
        }
    }
    printf("ibgeks_encrypt: avg-%.3f\n", cost1/sum);

    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        peks_encrypt(Ca, Cb, pairing, g, pk, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost2 += time_cost(start, end);
            printf("%.3f\n", cost2);
            gettimeofday(&start, NULL);
        }
    }
    printf("peks_encrypt: avg-%.3f\n", cost2/sum);

    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        sa_peks_encrypt(Ca, Cb, pairing, g, pk, N, e, d, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost3 += time_cost(start, end);
            printf("%.3f\n", cost3);
            gettimeofday(&start, NULL);
        }
    }
    printf("sa_peks_encrypt: avg-%.3f\n", cost3/sum);

    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        paeks_encrypt(Ca, Cb2, pairing, g, pk, sk2, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost4 += time_cost(start, end);
            printf("%.3f\n", cost4);
            gettimeofday(&start, NULL);
        }
    }
    printf("paeks_encrypt: avg-%.3f\n", cost4/sum);

    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        paeks20_encrypt(Ca, Cb, pairing, g, pk, sk2, dataset[i]);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost5 += time_cost(start, end);
            printf("%.3f\n", cost5);
            gettimeofday(&start, NULL);
        }
    }
    printf("paeks20_encrypt: avg-%.3f\n", cost5/sum);


    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(gsk);
    element_clear(pk2);
    element_clear(sk2);
    element_clear(Ca);
    element_clear(Cb2);
    mpz_clear(N);
    mpz_clear(pi);
    mpz_clear(e);
    mpz_clear(d);
    pairing_clear(pairing);//必须最后清理
    fclose(fp);
    fclose(fw);
    return 0;
}
