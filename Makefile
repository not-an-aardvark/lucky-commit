default: lucky-commit.c
	gcc -Wall -std=c99 -pedantic -O3 -DNDEBUG -flto -lm -o lucky-commit lucky-commit.c -I/usr/local/opt/openssl/include/ -lcrypto -lz
