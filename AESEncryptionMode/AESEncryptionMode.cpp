// AESEncryptionMode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "CImg-2.4.1/CImg.h"
#include "AES.h"
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

#define BLOCK_SIZE 16
#define BLOCK_SIZE_BYTES 128

#define COLORS_NUMBER 3
#define SQUARE 2
#define ONE_DIMENSIONAL 1
#define Z_VALUE 0

typedef cimg_library::CImg<unsigned char> Image;

struct cbc_data {
	unsigned char* bytes;
	unsigned char* iv;
};

unsigned char* getImageBytes(Image image);
void saveImage(Image image, unsigned char* bytes, string path);
unsigned char* generate();
unsigned char* encryptECB(unsigned char* text, unsigned int size, unsigned char* key);
unsigned char* decryptECB(unsigned char* ciphertext, unsigned int size, unsigned char* key);
cbc_data encryptCBC(unsigned char* chyphertext, unsigned int size, unsigned char* key);
unsigned char* decryptCBC(cbc_data cbc, unsigned int size, unsigned char* key);
unsigned char** splitTextToBlocks(unsigned char* text, unsigned int blocks_number);

__declspec(selectany) cbc_data currResult;

using namespace std;

int main()
{
	Image initial("initial.bmp");
	unsigned int size = (unsigned int) initial.size();
	int width = initial.width();
	int height = initial.height();
	
	unsigned char* bytes = getImageBytes(initial);
	unsigned char* key = generate();
	
	unsigned char* encrypted_ECB_bytes = encryptECB(bytes, size, key);
	Image encrypted_ECB(width, height, ONE_DIMENSIONAL, COLORS_NUMBER);
	saveImage(encrypted_ECB, encrypted_ECB_bytes, "encrypted_ECB.bmp");
	delete(encrypted_ECB);

	Image encrypted_ECB_try_do_decrypt("encrypted_ECB.bmp");
	unsigned char* encrypted_ECB_try_do_decrypt_bytes = getImageBytes(encrypted_ECB_try_do_decrypt);
	unsigned char* decrypted_ECB_bytes = decryptECB(encrypted_ECB_try_do_decrypt_bytes, size, key);
	Image decrypted_ECB(width, height, ONE_DIMENSIONAL, COLORS_NUMBER);
	saveImage(decrypted_ECB, decrypted_ECB_bytes, "decrypted_ECB.bmp");
	delete(decrypted_ECB);
	
	currResult = encryptCBC(bytes, size, key);
	Image encrypted_CBC(width, height, ONE_DIMENSIONAL, COLORS_NUMBER);
	saveImage(encrypted_CBC, currResult.bytes, "encrypted_CBC.bmp");
	delete(encrypted_CBC);

	unsigned char* decrypted_CBC_bytes = decryptCBC(currResult, size, key);
	Image decrypted_CBC(width, height, ONE_DIMENSIONAL, COLORS_NUMBER);
	saveImage(decrypted_CBC, decrypted_CBC_bytes, "decrypted_CBC.bmp");
}

unsigned char* getImageBytes(Image image) {
	unsigned char* bytes = new unsigned char[image.size()];

	int i = 0;
	for (int x = 0; x < image.width(); x++) {
		for (int y = 0; y < image.height(); y++) {
			for (int color = 0; color < COLORS_NUMBER; color++) {
				bytes[i] = image(x, y, Z_VALUE, color);
				i++;
			}
		}
	}

	return bytes;
}

void saveImage(Image image, unsigned char* bytes, string path) {
	image.fill(0);

	int i = 0;
	for (int x = 0; x < image.width(); x++) {
		for (int y = 0; y < image.height(); y++) {
			for (int color = 0; color < COLORS_NUMBER; color++) {
				image(x, y, Z_VALUE, color) = bytes[i];
				i++;
			}
		}
	}

	image.save_bmp(path.c_str());
}

unsigned char* generate() {
	BYTE lpGoop[BLOCK_SIZE];
	HCRYPTPROV m_hProv;
	m_hProv = NULL;
	::CryptAcquireContext(&m_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (m_hProv == NULL)
		throw GetLastError();
	if (!CryptGenRandom(m_hProv, BLOCK_SIZE, lpGoop))
		printf("\r\nerror");
	if (m_hProv) ::CryptReleaseContext(m_hProv, 0);

	unsigned char* res = new unsigned char[BLOCK_SIZE];
	memcpy(res, lpGoop, BLOCK_SIZE);

	return res;
}

unsigned char* encryptECB(unsigned char* text, unsigned int size, unsigned char* key) {
	AES aes(BLOCK_SIZE_BYTES);
	unsigned int outLen = 0;
	return aes.EncryptECB(text, size, key, outLen);
}

unsigned char* decryptECB(unsigned char* ciphertext, unsigned int size, unsigned char* key) {
	AES aes(BLOCK_SIZE_BYTES);
	unsigned int outLen = 0;
	return aes.DecryptECB(ciphertext, size, key);
}

cbc_data encryptCBC(unsigned char* text, unsigned int size, unsigned char* key) {
	AES aes(BLOCK_SIZE_BYTES);

	unsigned char* iv = generate();
	unsigned char* prev_C = iv;

	unsigned int blocks_number = size / BLOCK_SIZE;
	unsigned char** P = splitTextToBlocks(text, blocks_number);

	unsigned char* ciphertext = new unsigned char[size];

	for (unsigned int block = 0; block < blocks_number; block++) {
		unsigned char* C = new unsigned char[BLOCK_SIZE];

		for (unsigned int byte = 0; byte < BLOCK_SIZE; byte++) {
			C[byte] = P[block][byte] ^ prev_C[byte];
		}

		unsigned int outLen = 0;
		C = aes.EncryptECB(C, BLOCK_SIZE, key, outLen);

		memcpy(ciphertext + block * BLOCK_SIZE, C, BLOCK_SIZE);
		
		if (prev_C != iv) {
			delete(prev_C);
		}
		
		prev_C = C;
	}

	cbc_data result = { ciphertext, iv };

	return result;
}

unsigned char* decryptCBC(cbc_data cbc, unsigned int size, unsigned char* key) {
	AES aes(BLOCK_SIZE_BYTES);

	unsigned int blocks_number = size / BLOCK_SIZE;
	unsigned char** C = splitTextToBlocks(cbc.bytes, blocks_number);

	unsigned char* prev_C = cbc.iv;

	unsigned char* text = new unsigned char[size];

	for (unsigned int block = 0; block < blocks_number; block++) {
		unsigned char* P = aes.DecryptECB(C[block], BLOCK_SIZE, key);

		for (unsigned int byte = 0; byte < BLOCK_SIZE; byte++) {
			P[byte] ^= prev_C[byte];
		}

		memcpy(text + (block * BLOCK_SIZE), P, BLOCK_SIZE);

		prev_C = C[block];

		delete P;
	}

	return text;
}

unsigned char** splitTextToBlocks(unsigned char* text, unsigned int blocks_number) {
	unsigned char** splitted_text = new unsigned char*[blocks_number];
	for (unsigned int i = 0; i < blocks_number; i++) {
		splitted_text[i] = text + (i * BLOCK_SIZE);
	}

	return splitted_text;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
