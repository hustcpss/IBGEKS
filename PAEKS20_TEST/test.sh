g++ -c PAEKS20.cpp
g++ -c test_main.cpp
g++ test_main.o PAEKS20.o -o test -lpbc -lgmp -lcrypto
./test 
