g++ -c PAEKS17.cpp
g++ -c test_main.cpp
g++ test_main.o PAEKS17.o -o test -lpbc -lgmp -lcrypto
./test 
