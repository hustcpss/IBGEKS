g++ -c IBGEKS.cpp
g++ -c test_main.cpp
g++ test_main.o IBGEKS.o -o test -lpbc -lgmp -lcrypto
./test 
