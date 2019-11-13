// AESEncryptionMode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "CImg-2.4.1/CImg.h"
#include "AES/AES.h"
#include <iostream>

#define BLOCK_SIZE 128

#define COLORS_NUMBER 3
#define SQUARE 2
#define ONE_DIMENSIONAL 1
#define Z_VALUE 0

typedef cimg_library::CImg<unsigned char> Image;

using namespace std;

int main()
{
    std::cout << "Hello World!\n"; 
}

unsigned char* loadImage(string path) {
	Image image(path.c_str());

	int image_size = image.size();
	unsigned char* bytes = new unsigned char[image_size];

	for (unsigned int i = 0; i < image_size; i++) {
		bytes[i] = image.at(i);
	}

	return bytes;
}

void saveImage(unsigned char* text, string path) {
	Image image(text, sizeof(text));
	image.fill(0);
	image.save_bmp(path.c_str());
}

unsigned char* generateKey() {

}

unsigned char* encryptECB(unsigned char* text, unsigned char* key) {
	AES aes(128);
	unsigned int outLen = 0;
	return aes.EncryptECB(text, sizeof(text) / sizeof(unsigned char), key, outLen);
}

unsigned char* decryptECB(unsigned char* ciphertext, unsigned char* key) {
	AES aes(128);
	unsigned int outLen = 0;
	return aes.EncryptECB(ciphertext, sizeof(ciphertext) / sizeof(unsigned char), key, outLen);
}

unsigned char* encryptCBC(unsigned char* text, unsigned char* key) {
	AES aes(128);

	unsigned char* iv = generateIV();

	unsigned char** splitted_text = splitTextToBlocks(text);

	unsigned char* ciphertext = new unsigned char[sizeof(text) / sizeof(unsigned char) + sizeof(iv) / sizeof(unsigned char)];

	memcpy(ciphertext, iv, sizeof(iv));

	for (unsigned int block = 0; block < sizeof(splitted_text) / sizeof(splitted_text[0]); block++) {
		int block_size = sizeof(splitted_text[block]);

		for (unsigned int byte = 0; byte < block_size; byte++) {
			splitted_text[block][byte] %= iv[byte];
		}

		memcpy(ciphertext + sizeof(iv) + block * BLOCK_SIZE, splitted_text[block], block_size);

		iv = splitted_text[block];
	}

	return ciphertext;
}

unsigned char* generateIV() {

}

unsigned char* decryptCBC(unsigned char* ciphertext, unsigned char* key) {
	AES aes(128);

	unsigned char** splitted_text = splitTextToBlocks(ciphertext);

	unsigned char* iv = splitted_text[0];

	unsigned char* text = new unsigned char[sizeof(ciphertext) / sizeof(unsigned char) - sizeof(iv) / sizeof(unsigned char)];

	unsigned int overlap = 0;

	for (unsigned int block = 1; block < sizeof(splitted_text); block++) {
		unsigned char* next_iv = splitted_text[block];

		for (unsigned int byte = 0; byte < BLOCK_SIZE; byte++) {
			splitted_text[block][byte] %= iv[byte];
		}

		memcpy(text + overlap, splitted_text[block], BLOCK_SIZE);

		iv = next_iv;
	}

	return text;
}

unsigned char** splitTextToBlocks(unsigned char* text) {
	unsigned int blocks_number = sizeof(text) / BLOCK_SIZE;

	unsigned int overlap = 0;

	unsigned char** splitted_text = new unsigned char*[blocks_number];
	for (int i = 0; i < blocks_number; i++) {
		splitted_text[i] = new unsigned char[BLOCK_SIZE];
		memcpy(text + i * BLOCK_SIZE, splitted_text[i], BLOCK_SIZE);
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
