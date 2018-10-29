#include <stdio.h>
#include <stdlib.h>

void prompt(){
	char ZZbuf[101];

	gets(ZZbuf);
	printf("You entered: %s\n", ZZbuf);

}

int main(){
	prompt();

	return 0;
}

void target(){
	printf("Haha! You got pwned!\n");
	exit(0);
}
