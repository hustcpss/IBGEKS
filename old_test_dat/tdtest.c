#include "paeks.h"
#include "paeks20.h"
#include "ibgeks.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
//只负责存储公开参数和私钥

static double time_cost(struct timeval A, struct timeval B) {
    double res;
    res = (B.tv_sec - A.tv_sec) * 1000000 + B.tv_usec - A.tv_usec;
    return res / 1000; 
}


int main(int argc, char * argv[]) {
    
    char * param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    //椭圆曲线type-f BN256

    pairing_t pairing;
    element_t g, pk, sk, gsk, pk2, sk2, Tw, Tw2;//PK：生成元g、公钥g^s、私钥s
    mpz_t N, pi, e, d, phi_N;//大整数N、延迟验证私钥pi=2^T mod phi—N
    int sum;
    char string[16];
    char tmp[8];
    struct timeval start, end;
    double cost;

    FILE * fp;
    
    sum = atoi(argv[1]);//测试的数据量
    
    //初始化pairing
    pairing_init_set_str(pairing, param);

    element_init_G1(Tw, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);
    element_init_G1(pk2, pairing);
    element_init_G1(gsk, pairing);
    element_init_Zr(sk, pairing);
    element_init_Zr(sk2, pairing);
    element_init_GT(Tw2, pairing);
    
    //原始PEKS的公私钥是相同的一套
    paeks_setup(pairing, g, pk, sk, pk2, sk2);
    ibgeks_join(pairing, "ID0", sk, gsk);

    gettimeofday(&start, NULL);
    ibgeks_trapdoor(Tw, sk, "gather");
    gettimeofday(&end, NULL);
    printf("ibgeks_trapdoor: %.3f\n", time_cost(start, end));

    cost = 0.0;
    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        paeks_trapdoor(Tw2, pairing, sk, pk2, "gather");
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost += time_cost(start, end);
            printf("batch %d: %.3f\n", i, cost);
            gettimeofday(&start, NULL);
        }
    }
    printf("paeks_trapdoor: total-%.3f\n", cost/sum);

    cost = 0.0;
    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        paeks20_trapdoor(Tw, pairing, sk, pk2, "gather");
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost += time_cost(start, end);
            printf("batch %d: %.3f\n", i+1, cost);
            gettimeofday(&start, NULL);
        }
    }
    printf("paeks20_trapdoor: total-%.3f\n", cost/sum);

    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(pk2);
    element_clear(sk2);
    element_clear(gsk);
    pairing_clear(pairing);//必须最后清理    
    return 0;
}
