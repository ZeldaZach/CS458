vuln: vuln_program.c
	gcc ./vuln_program.c -fno-stack-protector -z execstack -static -o vuln_program -std=c99 -ggdb -Wno-deprecated-declarations

clean:
	rm -f vuln_program
