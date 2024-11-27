g++ -c SA_PEKS.cpp
g++ -c test_main.cpp
g++ test_main.o SA_PEKS.o -o test -lpbc -lgmp -lcrypto
./test 
