#include "pch.h"
#include <string>
#include <iostream>
#include "AES.h"

AES::~AES() {
	delete[] round_keys;
}

void AES::SetKey(int key_size, unsigned char* key) {
	Nk = key_size;
	if (Nk == 4) {
		Nr = 10;
	}
	else if (Nk == 6) {
		Nr = 12;
	}
	else if (Nk == 8) {
		Nr = 14;
	}

	if (round_keys != nullptr) {
		delete[] round_keys;
	}
	round_keys = new unsigned char[(Nr + 1)*bytes];
	KeyExpansion(key, round_keys);
}

void AES::encrypt(unsigned char* text) {
	AddRoundKey(text, 0);
	for (int i = 1; i < Nr; ++i) {
		SubBytes(text);
		ShiftRows(text);
		MixColumns(text);
		AddRoundKey(text, i);
	}
	SubBytes(text);
	ShiftRows(text);
	AddRoundKey(text, Nr);
}

void AES::decrypt(unsigned char* text) {
	AddRoundKey(text, Nr);
	for (int i = 1; i < Nr; ++i) {
		InvShiftRows(text);
		InvSubBytes(text);
		AddRoundKey(text, Nr - i);
		InvMixColumns(text);
	}
	InvShiftRows(text);
	InvSubBytes(text);
	AddRoundKey(text, 0);
}

void AES::AddRoundKey(unsigned char* text, int round) {
	for (int i = 0; i < bytes; ++i) {
		text[i] ^= round_keys[round * bytes + i];
	}
}

void AES::KeyExpansion(unsigned char* key /* 4*key_len elements*/,
	unsigned char* w /* 16*(num_rounds+1) elements*/) {
	unsigned char temp[4];
	for (int i = 0; i < Nk*Nb; ++i) {
		w[i] = key[i];
	}
	for (int i = Nk; i < Nb*(Nr + 1); ++i) {
		for (int j = 0; j < Nb; ++j) {
			temp[j] = w[(i - 1)*Nb + j];
		}
		if (i % Nk == 0) {
			RotWord(temp);
			SubWord(temp);
			temp[0] ^= RCon[i / Nk];
		}
		else if (Nk > 6 && i % Nk == 4) {
			SubWord(temp);
		}
		for (int j = 0; j < Nb; ++j) {
			w[i*Nb + j] = w[(i - Nk)*Nb + j] ^ temp[j];
		}
	}
}

void AES::SubBytes(unsigned char a[16]) {
	for (size_t i = 0; i < 16; ++i) {
		a[i] = S_box[a[i]];
	}
}

void AES::InvSubBytes(unsigned char a[16]) {
	for (size_t i = 0; i < 16; ++i) {
		a[i] = Inv_S_box[a[i]];
	}
}

void AES::ShiftRows(unsigned char a[16]) {
	unsigned char tmp[16];

	tmp[0] = a[0];
	tmp[1] = a[5];
	tmp[2] = a[10];
	tmp[3] = a[15];

	tmp[4] = a[4];
	tmp[5] = a[9];
	tmp[6] = a[14];
	tmp[7] = a[3];

	tmp[8] = a[8];
	tmp[9] = a[13];
	tmp[10] = a[2];
	tmp[11] = a[7];

	tmp[12] = a[12];
	tmp[13] = a[1];
	tmp[14] = a[6];
	tmp[15] = a[11];

	memcpy(a, tmp, 16);
}


void AES::InvShiftRows(unsigned char a[16]) {
	unsigned char tmp[16];

	tmp[0] = a[0];
	tmp[1] = a[13];
	tmp[2] = a[10];
	tmp[3] = a[7];

	tmp[4] = a[4];
	tmp[5] = a[1];
	tmp[6] = a[14];
	tmp[7] = a[11];

	tmp[8] = a[8];
	tmp[9] = a[5];
	tmp[10] = a[2];
	tmp[11] = a[15];

	tmp[12] = a[12];
	tmp[13] = a[9];
	tmp[14] = a[6];
	tmp[15] = a[3];

	memcpy(a, tmp, 16);
}

unsigned char mult2(unsigned char p) { // multiply by x
	unsigned char is_high_bit = p & 0x80;
	unsigned char with_shift = (p << 1) & 0xff;
	return is_high_bit == 0 ? with_shift : with_shift ^ 0x1b;
}

unsigned char mult3(unsigned char p) { // multiply by x+1
	return mult2(p) ^ p;
}

void AES::MixColumns(unsigned char a[16]) {
	unsigned char tmp[16];
	for (int c = 0; c < 4; ++c) {
		tmp[c * 4] = (unsigned char)(mult2(a[c * 4]) ^ mult3(a[c * 4 + 1]) ^ a[c * 4 + 2] ^ a[c * 4 + 3]);
		tmp[c * 4 + 1] = (unsigned char)(a[c * 4] ^ mult2(a[c * 4 + 1]) ^ mult3(a[c * 4 + 2]) ^ a[c * 4 + 3]);
		tmp[c * 4 + 2] = (unsigned char)(a[c * 4] ^ a[c * 4 + 1] ^ mult2(a[c * 4 + 2]) ^ mult3(a[c * 4 + 3]));
		tmp[c * 4 + 3] = (unsigned char)(mult3(a[c * 4]) ^ a[c * 4 + 1] ^ a[c * 4 + 2] ^ mult2(a[c * 4 + 3]));
	}
	memcpy(a, tmp, 16);
}

unsigned char GFMul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char hi_bit_set;
	for (int counter = 0; counter < 8; counter++) {
		if ((b & (unsigned char)(1)) != 0) {
			p ^= a;
		}
		hi_bit_set = (unsigned char)(a & (unsigned char)(0x80));
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}

void AES::InvMixColumns(unsigned char a[16]) {
	unsigned char tmp[16];
	for (int c = 0; c < 4; ++c) {
		tmp[c * 4] = (unsigned char)(GFMul(0x0e, a[c * 4]) ^ GFMul(0x0b, a[c * 4 + 1]) ^ GFMul(0x0d, a[c * 4 + 2]) ^ GFMul(0x09, a[c * 4 + 3]));
		tmp[c * 4 + 1] = (unsigned char)(GFMul(0x09, a[c * 4]) ^ GFMul(0x0e, a[c * 4 + 1]) ^ GFMul(0x0b, a[c * 4 + 2]) ^ GFMul(0x0d, a[c * 4 + 3]));
		tmp[c * 4 + 2] = (unsigned char)(GFMul(0x0d, a[c * 4]) ^ GFMul(0x09, a[c * 4 + 1]) ^ GFMul(0x0e, a[c * 4 + 2]) ^ GFMul(0x0b, a[c * 4 + 3]));
		tmp[c * 4 + 3] = (unsigned char)(GFMul(0x0b, a[c * 4]) ^ GFMul(0x0d, a[c * 4 + 1]) ^ GFMul(0x09, a[c * 4 + 2]) ^ GFMul(0x0e, a[c * 4 + 3]));
	}
	memcpy(a, tmp, 16);
}


void AES::SubWord(unsigned char a[4]) {
	for (size_t i = 0; i < 4; ++i) {
		a[i] = S_box[a[i]];
	}
}

void AES::RotWord(unsigned char a[4]) {
	unsigned char tmp[4];

	tmp[0] = a[1];
	tmp[1] = a[2];
	tmp[2] = a[3];
	tmp[3] = a[0];

	memcpy(a, tmp, 4);
}
