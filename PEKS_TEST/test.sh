g++ -c PEKS.cpp
g++ -c test_main.cpp
g++ test_main.o PEKS.o -o test -lpbc -lgmp -lcrypto
./test 
