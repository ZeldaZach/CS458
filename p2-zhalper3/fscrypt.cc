#include "fscrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Useful: BF_set_key, BF_cbc_encrypt, BF_ecb_encrypt
 * Can only use BF_ecb_encrypt
 * https://www.openssl.org/docs/man1.0.2/crypto/blowfish.html
 */

BF_KEY bf_key;

const char init_vector[] = "00000000"; // 8 zeroes for each block

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	// Zero out the memory for buffer
	unsigned char *output = (unsigned char *)calloc(bufsize, sizeof(char));
	unsigned char *output_head = output; // Keep it so we can return it :)

	// Establish BlowFish Key
	BF_set_key(&bf_key, BLOCKSIZE * 2, (const unsigned char *)keystr);

	// Make pointer to play with plaintext
	unsigned char *pt_counter = (unsigned char *)plaintext;

	// Boxes to do the math
	unsigned char *bf_boxes = (unsigned char *)calloc(bufsize, sizeof(char));

	// XOR plaintext block with IV
	for (int i = 0; i < BLOCKSIZE; i++)
	{
		bf_boxes[i] = init_vector[i] ^ *(pt_counter++);
	}

	// First iter of ECB
	BF_ecb_encrypt(&bf_boxes[0], output, &bf_key, BF_ENCRYPT);

	// Address cascading blocks now
	bufsize -= BLOCKSIZE;
	int start_char = BLOCKSIZE, box_index = BLOCKSIZE;
	while (bufsize > 0)
	{
		for (int i = 0; i < BLOCKSIZE; i++)
		{
			bf_boxes[box_index++] = *(output++) ^ *(pt_counter++); // XOR
		}
		
		BF_ecb_encrypt(&bf_boxes[start_char], output, &bf_key, BF_ENCRYPT);
		start_char += BLOCKSIZE;
		bufsize -= BLOCKSIZE;
	}

	// Set the result length
	*resultlen = strlen((const char *) output_head);

	return (void *)output_head;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
	// Zero out the memory for buffer
	unsigned char *output = (unsigned char *)calloc(bufsize + 1, sizeof(char));
	unsigned char *bf_boxes = (unsigned char *)calloc(bufsize + 1, sizeof(char));
	unsigned char *bf_boxes_ptr = bf_boxes;
	unsigned char *ct_counter_outer = (unsigned char *)ciphertext;
	unsigned char *ct_counter_inner = (unsigned char *)ciphertext;

	BF_set_key(&bf_key, BLOCKSIZE * 2, (const unsigned char *)keystr);

	BF_ecb_encrypt(ct_counter_outer, output, &bf_key, BF_DECRYPT);

	for (int i = 0; i < BLOCKSIZE; i++)
	{
		bf_boxes[i] = init_vector[i] ^ *(output++);
	}

	bufsize -= BLOCKSIZE;
	int box_index = BLOCKSIZE;
	while (bufsize > 0)
	{
		ct_counter_outer += BLOCKSIZE;
		BF_ecb_encrypt(ct_counter_outer, output, &bf_key, BF_DECRYPT);

		for (int i = 0; i < BLOCKSIZE; i++)
		{
			bf_boxes[box_index++] = *(ct_counter_inner++) ^ *(output++);
		}

		bufsize -= BLOCKSIZE;
	}

	*resultlen = strlen((const char *)bf_boxes_ptr) + 1; // Had to add 1 to fix main.cc test
	return (void *)bf_boxes_ptr;
}