#!/bin/sh
gcc -c peks.c
gcc -c sa_peks.c
gcc -c ibgeks.c
gcc -c paeks.c
gcc -c paeks20.c
gcc -c single_enc.c
echo "multi sender"
# gcc peks.o sa_peks.o ibgeks.o paeks.o paeks20.o single_enc.o -o encrypt -lpbc -lgmp -lcrypto
# ./encrypt 1000
# echo ""

# gcc -c single_td.c
# echo "trapdoor"
# gcc peks.o sa_peks.o ibgeks.o paeks.o paeks20.o single_td.o -o td -lpbc -lgmp -lcrypto
# ./td 1000
# echo ""

# gcc -c single_test.c
# echo "test"
# gcc peks.o sa_peks.o ibgeks.o paeks.o paeks20.o single_test.o -o tt -lpbc -lgmp -lcrypto
# ./tt 1000


gcc -c tdtest.c

gcc peks.o sa_peks.o ibgeks.o paeks.o paeks20.o tdtest.o -o mtd -lpbc -lgmp -lcrypto

./mtd 1000