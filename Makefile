all: rc6

rc6: rc6.cpp
	g++ rc6.cpp -o rc6 -Wall -Wextra -pedantic -std=c++14

.PHONY:
	clean

clean:
	rm -f rc6
