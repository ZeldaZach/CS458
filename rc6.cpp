#include <iostream>
#include <cmath>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

class RC6 {
	public:
		RC6(std::string);
		std::string encrypt(std::vector<unsigned long>);
		std::string decrypt(std::vector<unsigned long>);

		static void remove_spaces(std::string &);
	private:
		int left_rotate(int, unsigned int);
		int right_rotate(int, unsigned int);
		std::string hex2str(unsigned long);
		void seed_key(std::string);

	private:
		const int W = 32;
		const int R = 20;
		const int modulo = pow(2, W);
		std::vector<unsigned long> Seeded_keys;
};

RC6::RC6(std::string user_key)
{
	Seeded_keys.resize(2 * R + 4);
	seed_key(user_key);
}

std::string RC6::encrypt(std::vector<unsigned long> plaintext_blocks)
{
	unsigned long A = plaintext_blocks.at(0);
	unsigned long B = plaintext_blocks.at(1);
	unsigned long C = plaintext_blocks.at(2);
	unsigned long D = plaintext_blocks.at(3);

	B = (B + Seeded_keys[0]) % modulo;
	D = (D + Seeded_keys[1]) % modulo;

	for (int i = 1; i <= R; i++)
	{
		unsigned long t = (left_rotate((B * (2 * B + 1)), log2(W))) % modulo;
		unsigned long u = (left_rotate((D * (2 * D + 1)), log2(W))) % modulo;
		A = (left_rotate((A ^ t), u) + Seeded_keys[2 * i]) % modulo;
		C = (left_rotate((C ^ u), t) + Seeded_keys[2 * i + 1]) % modulo;

		unsigned long hold = A;
		A = B;
		B = C;
		C = D; 
		D = hold;
	}

	A = (A + Seeded_keys[2 * R + 2]) % modulo;
	C = (C + Seeded_keys[2 * R + 3]) % modulo;

	std::string return_string = hex2str(A) + hex2str(B) + hex2str(C) + hex2str(D);
	return return_string;
}

std::string RC6::decrypt(std::vector<unsigned long> )//ciphertext_blocks)
{
	return "";
}

void RC6::seed_key(std::string user_key)
{
	unsigned long P = 0xB7E15163;
	unsigned long Q = 0x9E3779B9;
	unsigned long C = std::ceil(32 / W);

	std::vector<unsigned long> L;
	L.resize(C);

	for (int i = 0; i < static_cast<int>(C); i++)
	{
    	L.at(i) = std::strtoul(user_key.substr(i * 8, 8).c_str(), nullptr, 16);
	}

	Seeded_keys[0] = P;
	for (int i = 1; i <= 2 * R + 3; i++)
	{
		Seeded_keys[i] = (Seeded_keys[i-1] + Q) % modulo;
	}

	int A = 0, B = 0, i = 0, j = 0;
	unsigned long v = 3 * std::max(C, static_cast<unsigned long>(2 * R + 4));

	for (int s = 1; s <= static_cast<int>(v); s++)
	{
		A = Seeded_keys[i] = left_rotate((Seeded_keys[i] + A + B), 3);
		B = L[j] = left_rotate((L[j] + A + B), A + B);
		i = (i + 1) % (2 * R + 4);
		j = (j + 1) % C;
	}
}

/* Source: GeeksForGeeks */
int RC6::left_rotate(int n, unsigned int d)
{
   return (n << d) | (n >> (32 - d));
}

/* Source: GeeksForGeeks */
int RC6::right_rotate(int n, unsigned int d)
{
   return (n >> d) | (n << (32 - d));
}

/* Source: StackOverflow #12851379 */
std::string RC6::hex2str(unsigned long hex_value)
{
	std::stringstream ss;
	ss << std::setfill('0') << std::setw(4) << std::hex << hex_value;
	return ss.str();
}

/* StackOverflow #83439 */
void RC6::remove_spaces(std::string &str)
{
	std::string::iterator end_pos = std::remove(str.begin(), str.end(), ' ');
	str.erase(end_pos, str.end());
}

/* Usage: ./rc6 ./input_file.txt ./output_file.txt */
int main(int argc, const char **argv)
{
	if (argc != 2)
	{
		std::cerr << "Usage: ./rc6 ./input.txt ./output.txt" << std::endl;
		return 1;
	}

	std::ifstream input_file;
	input_file.open(argv[1]);

	// Read file contents
	std::vector<std::string> file_lines;
	if (input_file.is_open())
	{
		std::string line;
		while (getline(input_file, line))
		{
			file_lines.push_back(line);
		}
		input_file.close();
	}
	else
	{
		std::cerr << "Unable to open " << argv[1] << std::endl;
		return 1;
	}

	if (file_lines.size() != 3)
	{
		std::cerr << "Incorrect file format " << argv[1] << std::endl;
		return 2;
	}

	std::string mode = file_lines.at(0);
	std::string text = file_lines.at(1).substr(file_lines.at(1).find_first_of(":") + 1);
	std::string user_key = file_lines.at(2).substr(file_lines.at(2).find_first_of(":") + 1);

	RC6::remove_spaces(mode);
	RC6::remove_spaces(user_key);
	RC6::remove_spaces(text);

	std::cout << mode << std::endl << user_key << std::endl << text << std::endl;

	RC6 algorithm_object(user_key);

	std::vector<unsigned long> blocks;
	for (int i = 0; i < static_cast<int>(text.length()); i += 8)
	{
		blocks.push_back(std::stoul(text.substr(i, 8), nullptr, 16));
	}

	if (mode == "Encryption")
	{
		std::cout << algorithm_object.encrypt(blocks) << std::endl;
	}
	else
	{
		algorithm_object.decrypt(blocks);
	}

	return 0;
}