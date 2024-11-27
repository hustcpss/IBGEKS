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
    element_t g, pk, sk, gsk;//PK：生成元g、公钥g^s、私钥s
    int sum;
	char string[16];
	char tmp[8];
    struct timeval start, end;
    double cost;

    FILE * fp;
    
    sum = atoi(argv[1]);//测试的数据量

    //初始化pairing
    pairing_init_set_str(pairing, param);

    element_init_G1(pk, pairing);
    element_init_G1(gsk, pairing);
    element_init_Zr(sk, pairing);

    cost = 0.0;
    gettimeofday(&start, NULL);
    for(int i = 0; i < sum; i++) {
        ibgeks_join(pairing, "ID", sk, gsk);
        if(i % 50 == 49) {
            gettimeofday(&end, NULL);
            cost += time_cost(start, end);
            printf("%.3f\n", cost);
            gettimeofday(&start, NULL);
        }
    }
    printf("ibgeks_join: avg-%.3f\n", cost/sum);

    element_clear(pk);
    element_clear(sk);
    element_clear(gsk);
    pairing_clear(pairing);//必须最后清理    
    return 0;
}
