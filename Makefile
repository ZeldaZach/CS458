all: rc6

.PHONY: all rc6 clean

rc6: rc6.cpp
	g++ rc6.cpp -o rc6 -g -std=c++11 -Wall -Wextra -pedantic

clean:
	rm -rf rc6 rc6.dSYM/
