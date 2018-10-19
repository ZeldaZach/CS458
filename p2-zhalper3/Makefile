FLAGS = -Wall -Wextra -pedantic -std=c++14 -Wno-vla-extension
OPENSSL = -I/usr/local/Cellar/openssl/1.0.2p/include -L/usr/local/Cellar/openssl/1.0.2p/lib

all: fscrypt run

fscrypt: fscrypt.cc main.cc
	g++ $(FLAGS) $(OPENSSL) main.cc fscrypt.cc -lcrypto -o fscrypt 

run: fscrypt
	./fscrypt

clean:
	rm fscrypt

.PHONY: clean run
