#pragma once

#include <iostream>
#include "const_values.h"

using namespace std;

unsigned char mult2(unsigned char p);
unsigned char mult3(unsigned char p);
unsigned char GFMul(unsigned char a, unsigned char b);

class AES {
public:
	AES() {}
	~AES();
	void SetKey(int key_size, unsigned char* key);
	void encrypt(unsigned char* text);
	void decrypt(unsigned char* text);
private:
	const int bytes = 16;
	int Nb = 4; // BLOCK SIZE
	int Nk; // KEY LENGHT 4 (128), 6 (192), 8 (256)
	int Nr; // NUMBER OF ROUNDS
	unsigned char* round_keys;

	void AddRoundKey(unsigned char* text, int round);
	void KeyExpansion(unsigned char* key, unsigned char* w);
	void SubBytes(unsigned char a[16]);
	void ShiftRows(unsigned char a[16]);
	void MixColumns(unsigned char a[16]);

	void InvSubBytes(unsigned char a[16]);
	void InvShiftRows(unsigned char a[16]);
	void InvMixColumns(unsigned char a[16]);

	void SubWord(unsigned char a[4]);
	void RotWord(unsigned char a[4]);

};