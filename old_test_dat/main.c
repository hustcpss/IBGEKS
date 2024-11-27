// main.c
#include <stdio.h>
#include "/usr/local/include/pbc/pbc.h"
int main(int argc, char const *argv[]) {
  // 初始化pairing
  pairing_t pairing;  
  // pairing_t定义： pairings where elements belong本例子用a.param去初始化pairing; a pairing is a map 例如:e:G1×G2->Gt
  // a.param是pbc库中标准的参数集，其提供对称的pairing ，在所有的param中有最高的速度。
  char * param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    
  pairing_init_set_str(pairing, param);
  // 生成x
  element_t x;
  element_init_Zr(x, pairing); //用pairing初始化x
  element_random(x); //随机生成x
  element_printf("%B\n", x); //打印x

  return 0;
}
