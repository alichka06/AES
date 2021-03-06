#include "pch.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <string>

#include "AES.h"

using namespace std;

int main()
{
	unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	AES aes4;
	aes4.SetKey(4, key);

	char* file_test = new char[16];
	ifstream infile;
	infile.open("small.txt", ios::binary | ios::in);
	
	char* huge_arr = new char[1500000000];
	int n = 0;
	while (infile) {
		//char* temp = new char[16];
		infile.read(&huge_arr[n * 16], 16);
		//aes4.encrypt((unsigned char*)(huge_arr));
		//aes4.decrypt((unsigned char*)(huge_arr));
		//memcpy(&huge_arr[(n - 1) * 16], temp, 16);
		++n;

	}
	infile.close();

	clock_t begin = clock();
	for (int j = 0; j < n; j++) {
		aes4.encrypt((unsigned char*)(&huge_arr[j*16]));
	}

	clock_t end = clock();
	double elapsed_secs = (double)(end - begin) / CLOCKS_PER_SEC;
	cout << "Time " << elapsed_secs;
	
	begin = clock();

	for (int j = 0; j < n; j++) {
		aes4.decrypt((unsigned char*)(&huge_arr[j * 16]));
	}

	end = clock();
	elapsed_secs = (double)(end - begin) / CLOCKS_PER_SEC;
	cout << " Time " << elapsed_secs;


	ofstream outfile;
	outfile.open("small_out.txt", ios::binary | ios::out);
	for (int j = 0; j < n; ++j) {
		for (int i = 0; i < 16; ++i) {
			outfile << huge_arr[j*16+i];
		}
	}
	outfile.close();

	delete[] huge_arr;
	return 0;
}
