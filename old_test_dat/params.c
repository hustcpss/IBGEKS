#include "peks.h"
#include "ibgeks.h"
#include "paeks.h"
#include <stdlib.h>
#include <string.h>
//只负责存储公开参数和私钥

int g1_len, gt_len, zr_len;

int save_param(FILE *fp, element_t g, element_t pk, element_t sk, element_t gsk, element_t pk2, element_t sk2, mpz_t N, mpz_t pi, mpz_t e, mpz_t d) {
    //保存公私钥等信息
    unsigned char g1_buf[g1_len], zr_buf[zr_len];

    element_to_bytes_compressed(g1_buf, g);
    fwrite(g1_buf, g1_len, 1, fp);

    element_to_bytes_compressed(g1_buf, pk);
    fwrite(g1_buf, g1_len, 1, fp);

    element_to_bytes(zr_buf, sk);
    fwrite(zr_buf, zr_len, 1, fp);

    element_to_bytes_compressed(g1_buf, gsk);
    fwrite(g1_buf, g1_len, 1, fp);

    element_to_bytes_compressed(g1_buf, pk2);
    fwrite(g1_buf, g1_len, 1, fp);
    
    element_to_bytes(zr_buf, sk2);
    fwrite(zr_buf, zr_len, 1, fp);

    mpz_out_raw(fp, N);
    mpz_out_raw(fp, pi);
    mpz_out_raw(fp, e);
    mpz_out_raw(fp, d);
    return 0;    
}

int catalyst_setup(mpz_t N, mpz_t pi, mpz_t e, mpz_t d, mpz_t phi_N) {
//确定参数
//与T无关的直接设定，short-cut根据T的不同来生成
    
    gmp_randstate_t rndst;
    mpz_t p, q;

    mpz_init(p);
    mpz_init(q);

    //选择两个大素数p,q，计算N=pq
    mpz_set_str(p, "DD848D47E193DCF0F57DD9256ABF10B5869C2D5D600C21A4D36C29659C062542B5CDCB6CF1002D7177D720472078AFC0193BAD7E0FCE7C07CABC83526F71CF2881993188748C07C52CF73D1A09BF38F22163909A7EBAEEC9A9D9019F6CE919AEF18BCD995F80E7823370D500B53DC85D169F4FBA383C9A2E7DA2393A11A9B171C86957B82E8115F9FB19670466155E50E41ADF91FB392EBC53614A475F58F9959972E56346993923991BD15110D2393513243DFEB2C28FCDFA067535E7A8A4DF", 16);
	mpz_set_str(q, "F9CE5FD04C169FC42F3C24C9E149EDCA7513A02648628C9AB80A9E9CE6F1FCD7EF4EA0FBC5AD4BE3E2B199A99969B74901B46BAF632A3B653A2E0FDC37D9D44646247C104EAB0A38027725886DCCAC682A3E71A84F57E5CE3FAF8C6DD7DEA27207AD6B3FBDDD51A4898884FB9C4853826C2836987179D4359122308CC6D44987562800D136BFB01CB3611E66B0F862EFA0E3769BE3795A9A75CA36A69E60851111849F8F0B8D46C5ACE50FCA7157B48B991C5AE30BC7B4198C464302C477CD0F", 16);
	mpz_set_str(N, "D82880FD0837BB93E10E5BA1FEEFDA5CD2BB6C888FF5B799A6AE77DCCA7A9A7CD49E9E51D7A309669CD60F6BA25025E6B0DEE9AD3C8FA710D47943639EDD9CF2EEBCFF6E868E8B30E60FFCE6A54B05B4CB18E70E4402B9C7ADC2519866A3F3986A6FE6D09531D19E1D9EC810609940629CE560CE4F59B4C4965976BDF31A11A5B6BB0F6E1F5C54B96EEC7C783B9A16A11700A65ED1FA39FE2253922585310BBB6FBAA9F634B17FA23F04591717EF8E27294C3EB1D1499EC5BFAF5BD01C3BF8E99ADD838C116676F803B84A10DEDB47E9D128DA1773A714B82C787CB469DCAB2DA10DD765505E1047F1DFE025279D80D23EAC4439B5CD353EF66D76A65E305D2BCAB625C7E3E6A24EFB5E6763BB3B925A24BEB4178FF720A7E94867D23E57D22E342EB3DDD67EA8D2E6F0A3E7F41BB0BA03D58F0D28491D07513347905CE9E9AD3DFDAE61DFAFE008016DAC6648F48CF47F531703A57A6987AB4F6B6DBAACBA0ABECDE2D2C5F52FFE91F1CE7728E5C1A4A607D796F0A007218F1A7D07FE913C11", 16);
	mpz_set_str(phi_N, "D82880FD0837BB93E10E5BA1FEEFDA5CD2BB6C888FF5B799A6AE77DCCA7A9A7CD49E9E51D7A309669CD60F6BA25025E6B0DEE9AD3C8FA710D47943639EDD9CF2EEBCFF6E868E8B30E60FFCE6A54B05B4CB18E70E4402B9C7ADC2519866A3F3986A6FE6D09531D19E1D9EC810609940629CE560CE4F59B4C4965976BDF31A11A5B6BB0F6E1F5C54B96EEC7C783B9A16A11700A65ED1FA39FE2253922585310BBB6FBAA9F634B17FA23F04591717EF8E27294C3EB1D1499EC5BFAF5BD01C3BF8E7C38A9673E3BBFA42DEFE4C2192D24969D5790C93CB386678A101B4B1E6E48912FBF16AFC99B096F2975726346DBB19C923BC2B0C42D47DD1F182E377B6E4B9BD02F8782F20AF9051CBF004C143AFACFFD91CB1D4C1E44C0FFFBFD9C4F990160D3AF57B04B9206FAC29F749EBA29594DA810E08BA7E92AEA3426EDDC9846BEEB41F6C55D87A6F19F152F326FB31E6CBB3FA54C0D5C6C7E030E223EA7FBCF33B6413D65DE073CEB0154BF0ED5BA6BBD3E3F9C73EB53215C33A08CDC4CF5270CA24", 16);
    mpz_set_str(e, "10001", 16);
	mpz_set_str(d, "403870723CD1CA221A5858B31D7A07675298AA9B3C2225C539B756173BF50717155876F31BDCED7B1617A7073477197B9B8AEEE4303D01C6C749ABD2DA2338B7014D4948ABCE5614F4F8D10DFA423006AE9557D1581B2D6C47A82ADB5D4ADBC403EE91B4966375F7D436176F307CC3AA9AD3BE793D4AFDAA3FE058B24E923BDBAA08ECD7EB3CE70BCCB190A9C47D31E7DB29ED20B816439DCFD7B5653F28CEEBA7A176D18BACBEDB6AB80AB058F140D7F78E2EC1555D3A2337AF392EB78FAF68B0ACFA3B74ACCDC0A0683CBC80B64CEFACAE8CB66817C1773E5674A98D8950C64DC4B1303F0CC96A3FB77D9EB6DAF0902E16E95B541EC76F70D7E40FB82CC1E0E5AAF9C44F4E9FA5F777C2F21D8ED8E1DA67F3EEDE2FEF0086E179F3D2145621D3A2382FA358CDA6903644007F897CBB2944C078FE49A5815413C9CABE1E5A646EE608965CA54E5E4C1DC881881D", 16);
    
    mpz_clear(p);
    mpz_clear(q);
    return STS_OK;
}

int main(int argc, char * argv[]) {
    
	char * param = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    //椭圆曲线type-f BN256

    pairing_t pairing;
    element_t g, pk, sk, gsk, pk2, sk2;//PK：生成元g、公钥g^s、私钥s
    mpz_t N, pi, e, d, phi_N;//大整数N、延迟验证私钥pi=2^T mod phi—N
	char string[16];
	char tmp[8];

    FILE * fp;
    
    //初始化pairing
    pairing_init_set_str(pairing, param);
    g1_len = pairing_length_in_bytes_compressed_G1(pairing);
    gt_len = pairing_length_in_bytes_GT(pairing);
    zr_len = pairing_length_in_bytes_Zr(pairing);

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
	mpz_init(phi_N);

    //原始PEKS的公私钥是相同的一套
    paeks_setup(pairing, g, pk, sk, pk2, sk2);
    ibgeks_join(pairing, "ID0", sk, gsk);

	strcpy(string,"param.txt");
	fp = fopen(string, "wb");//存储各种参数
	catalyst_setup(N, pi, e, d, phi_N);
	save_param(fp, g, pk, sk, gsk, pk2, sk2, N, pi, e, d);		
	fclose(fp);	

    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    element_clear(pk2);
    element_clear(sk2);
    element_clear(gsk);
	mpz_clear(phi_N);
    mpz_clear(N);
    mpz_clear(pi);
    mpz_clear(e);
    mpz_clear(d);
    pairing_clear(pairing);//必须最后清理    
    return 0;
}
