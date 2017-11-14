default: lucky-commit.c
	gcc -Wall -std=c99 -pedantic -O3 -DNDEBUG -flto -pthread -o lucky-commit lucky-commit.c -I/usr/local/opt/openssl/include/ -lcrypto -lm -lz
