#define _CRT_SECURE_NO_DEPRECATE


#include <iostream>
#include <math.h>
#include <vector>
#include "RSA.h"
#include "DHK.h"

using namespace std;



int main() {
	RSA aRSA(11, 19);
	aRSA.RSA_generate();
	aRSA.print_info();


	string content = "hi";
	long long *ip = NULL;
	int count = 0;
	ip = aRSA.encryption(content, count);
	cout << "Before encryption: " << content << endl;
	cout << "After encryption:";
	for (int i = 0; i < count; i++){
		cout <<(char)ip[i] << " ";
	}
	cout << endl;
	string decryption;
	aRSA.decryption(ip, count, decryption);
	cout <<"After decryption: "<< decryption << endl;

	//long long a = pow(2000, 2000);
	//cout << a << endl;

	system("pause");
	return EXIT_SUCCESS;
}