#include <cmath>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

class RC6
{
	public:
		RC6(std::string);
		std::string encrypt(std::string);
		std::string decrypt(std::string);

	public:
		std::vector<unsigned int> S;

	private:
		unsigned int rotate_left(unsigned int, unsigned int);
		unsigned int rotate_right(unsigned int, unsigned int);
		std::string hex2str(unsigned int);
		void generate_keys();
		std::string little_endian(std::string);
		std::string hex_to_string(unsigned int A, unsigned int B, unsigned int C, unsigned int D);

	private:
		const unsigned int W = 32;
		const unsigned int R = 20;
		const unsigned long P = 0xB7E15163;
		const unsigned long Q = 0x9E3779B9;
		const unsigned long modulo = std::pow(2, W);
		const unsigned int LEN;
		const unsigned int C = std::ceil(static_cast<float>(LEN) / 4);
		const std::string USER_KEY;
};

RC6::RC6(std::string user_key) : LEN(user_key.length() / 2), USER_KEY(user_key)
{
	S.resize(2 * R + 4);
	std::fill(S.begin(), S.end(), 0);

	generate_keys();
}

std::string RC6::little_endian(std::string str){
  std::string endian;
  
  if(str.length() % 2 == 0){
    for(std::string::reverse_iterator r_it = str.rbegin();
	     r_it != str.rend();r_it = r_it + 2){
      endian.push_back(*(r_it+1));
      endian.push_back(*r_it);
    }
  }else{
    str = "0" + str;
    for(std::string::reverse_iterator r_it = str.rbegin();
      r_it != str.rend();r_it = r_it + 2){
      endian.push_back(*(r_it+1));
      endian.push_back(*r_it);
    }
  }

  return endian;
}

unsigned int RC6::rotate_left(unsigned int a, unsigned int b)
{
	//std::cout << "RL " << a << ", " << b << std::endl;
	b &= 0x1f;

	return ((a << b) | (a >> (W - b)));
}

unsigned int RC6::rotate_right(unsigned int a, unsigned int b)
{
	b &= 0x1f;
	return ((a >> b) | (a << (W - b)));
}

std::string RC6::hex_to_string(unsigned int A, unsigned int B, unsigned int C, unsigned int D){

  std::string strA, strB, strC, strD, result;

  std::stringstream ss;
  ss << std::setfill('0') << std::setw(4) <<std::hex << A;
  strA = little_endian(ss.str());
  ss.str("");
  ss.clear();

  ss << std::setfill('0') << std::setw(4) <<std::hex << B;
  strB = little_endian(ss.str());
  ss.str("");
  ss.clear();
  
  ss << std::setfill('0') << std::setw(4) <<std::hex << C;
  strC = little_endian(ss.str());
  ss.str("");
  ss.clear();

  ss << std::setfill('0') << std::setw(4) <<std::hex << D;
  strD = little_endian(ss.str());
  ss.str("");
  ss.clear();

  result = strA + strB + strC + strD;

  return result;

}

void RC6::generate_keys()
{
	std::vector<unsigned int> L;
	L.resize(C);

	for (int i = 0; i < static_cast<int>(L.size()); i++)
	{
		// Get the block
		std::string portion = USER_KEY.substr(8 * i, 8);
		portion = little_endian(portion);

		// Convert to hex unsigned int
		L.at(i) = std::strtoul(portion.c_str(), nullptr, 16);
	}

	S.at(0) = P;
	for (int i = 1; i < static_cast<int>(2 * R + 4); i++)
	{
		S.at(i) = (S.at(i - 1) + Q) % modulo;
	}

	unsigned int A, B, i, j;
	A = B = i = j = 0;
	int v = 3 * std::max(C, static_cast<unsigned int>(2 * R + 4));

	for (int k = 1; k <= v; k++)
	{
		A = S.at(i) = rotate_left((S.at(i) + A + B) % modulo, 3);  
		B = L.at(j) = rotate_left((L.at(j) + A + B) % modulo, (A + B));
		i = (i + 1) % (2 * R + 4);
		j = (j + 1) % C;
	}
}

/* Source: StackOverflow #12851379 */
std::string RC6::hex2str(unsigned int hex_value)
{
	std::stringstream ss;
	ss << std::setfill('0') << std::setw(4) << std::hex << hex_value;

	std::string compiled = little_endian(ss.str());

	/*compiled = compiled.substr(6, 2) + " " +
			   compiled.substr(4, 2) + " " +
			   compiled.substr(2, 2) + " " +
			   compiled.substr(0, 2);*/

	return compiled;
}

std::string RC6::decrypt(std::string message)
{
	std::vector<std::string> partitions;
	partitions.resize(4);
	for (int i = 0; i <= 24; i += 8)
	{
		std::string block = message.substr(i, 8);
		partitions.push_back(block);
	}

	unsigned int A = std::strtoul(partitions.at(0).c_str(), nullptr, 16);
	unsigned int B = std::strtoul(partitions.at(1).c_str(), nullptr, 16);
	unsigned int C = std::strtoul(partitions.at(2).c_str(), nullptr, 16);
	unsigned int D = std::strtoul(partitions.at(3).c_str(), nullptr, 16);

	C -= S.at(2 * R + 3);
	A -= S.at(2 * R + 2);

	for (int i = R; i >= 1; i--)
	{
		unsigned int hold = D;
		D = C;
		C = B;
		B = A;
		A = hold;

		unsigned int u = rotate_left((D * (2 * D + 1)) % modulo, log2(W));
		unsigned int t = rotate_left((B * (2 * B + 1)) % modulo, log2(W));

		C = rotate_right((C - S.at(2 * i + 1)) % modulo, t) ^ u;
		A = rotate_right((A - S.at(2 * i)) % modulo, u) ^ t;
	}

	D -= S.at(1);
	B -= S.at(0);

	std::string return_string = hex_to_string(A, B, C, D); //hex2str(A) + " " + hex2str(B) + " " + hex2str(C) + " " + hex2str(D);
	return return_string;
}

std::string RC6::encrypt(std::string message)
{
	std::vector<std::string> partitions;
	partitions.resize(4);
	for (int i = 0; i <= 24; i += 8)
	{
		std::string block = message.substr(i, 8);
		partitions.push_back(little_endian(block));
	}

	unsigned int A = std::strtoul(partitions.at(0).c_str(), nullptr, 16);
	unsigned int B = std::strtoul(partitions.at(1).c_str(), nullptr, 16);
	unsigned int C = std::strtoul(partitions.at(2).c_str(), nullptr, 16);
	unsigned int D = std::strtoul(partitions.at(3).c_str(), nullptr, 16);

	B += S.at(0);
	D += S.at(1);

	for (int i = 1; i <= static_cast<int>(R); i++)
	{
		unsigned int t = rotate_left((B * (2 * B + 1)) % modulo, log2(W));
		unsigned int u = rotate_left((D * (2 * D + 1)) % modulo, log2(W));

		A = rotate_left((A ^ t), u) + S.at(2 * i);
		C = rotate_left((C ^ u), t) + S.at(2 * i + 1);

		unsigned int hold = A;
		A = B;
		B = C;
		C = D;
		D = hold;
	}

	A += S.at(2 * R + 2);
	C += S.at(2 * R + 3);

	std::string return_string = hex_to_string(A, B, C, D);//hex2str(A) + " " + hex2str(B) + " " + hex2str(C) + " " + hex2str(D);
	return return_string;
}

void remove_spaces(std::string &str)
{
	str.erase(std::remove_if(str.begin(), str.end(), isspace), str.end());
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		std::cout << "Usage: ./rc6 ./input.txt ./output.txt" << std::endl;
		return 0;
	}

	std::ifstream file_input;
	file_input.open(argv[1]);
	if (!file_input.is_open())
	{
		std::cout << "Error opening file" << std::endl;
		return 1;
	}

	std::vector<std::string> lines;
	std::string line_str;
	while (getline(file_input, line_str))
	{
		lines.push_back(line_str);
	}

	std::string mode = lines.at(0);
	std::string text = lines.at(1).substr(lines.at(1).find_first_of(":") + 1);
	std::string key = lines.at(2).substr(lines.at(2).find_first_of(":") + 1);

	remove_spaces(mode);
	remove_spaces(text);
	remove_spaces(key);

	RC6 rc6(key);

	std::string result;
	std::string alt;
	
	if (mode.compare("Encryption") == 0)
	{
		result = rc6.encrypt(text);

		RC6 rc62(key);
		alt = rc62.decrypt(result);
	}
	else
	{
		result = rc6.decrypt(text);
	}

	std::cout << "original: " << text << std::endl;
	std::cout << "ciphertext: " << result << std::endl;
	std::cout << "plaintext: " << alt << std::endl;


}