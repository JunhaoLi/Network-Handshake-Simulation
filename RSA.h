#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int isPrime(int a, int b){ //determine whether is coprime by Eucilidian method
  int temp;
  while (b != 0){
    temp = b;
    b = a%b;
    a = temp;
  }
  return a == 1;
}

int get_prime(int low, int high, int prime){ // get a prime number which is coprime to prime
  int ui = (low % 2 == 0 ? low + 1 : low);
  int num = -1;
  for (; ui < high; ui += 2){
    if (isPrime(ui, prime)){
      num = ui;
      break;
    }
  }
  if (ui == high){//not found
    perror("Not found in get_prime");
    return -1;
  }
  else{
    return num;
  }
}

int get_inverse_modular(int e, int fai){  // get a modular inverse number
  int num = -1;
  for (int k = 1; k < 100; k++){
    if ((fai*k + 1) % e == 0){
      num = (fai*k + 1) / e;
      break;
    }
  }
  return num;
}


void RSA_generate(int p, int q,int *pub_n,int *pri_n, int *pub_e, int*pri_d){
  int n = p*q;
  int fai_n = (p - 1)*(q - 1);
  int e = get_prime(2, fai_n, fai_n);
  int d = get_inverse_modular(e, fai_n);
  *pub_n = n;
  *pri_n = n;
  *pub_e = e;
  *pri_d = d;
}


long long* encryption(const char *content, int len, int *count,int public_e, int public_n){  // using public key encrypt content
  long long *encrypt = NULL;
  *count = 0;
  if (len== 0){
    return encrypt;
  }
  
  for (int i = 0; i < len; i++){
    long long asc = content[i];
    long long ans = (long long)pow(asc, public_e) % public_n;
    long long *temp1 = (long long*)malloc((i+1)*sizeof(long long));
    for (int j = 0; j < i; j++){
      temp1[j] = encrypt[j];
    }
    temp1[i] = ans;
    if (encrypt != NULL){
      free(encrypt);
    }
    encrypt = temp1;
    (*count)++;
  }
  return encrypt;
}


char * decryption(long long* content, int count,int private_n){  //uisng private key decrypt content
  char *decrypt = NULL;
  if (count == 0){
    return decrypt;
  }
  for (int i = 0; i < count; i++){
    long long ans = content[i];
    ans = pow(ans, 5);
    ans = ans%private_n;
    ans = ans*ans*ans*ans;
    ans = ans%private_n;
    ans = pow(ans, 5);
    ans = ans%private_n;
    
    long long ans2= pow(content[i], 3);
    ans2 = ans2%private_n;
    long long ans3 = ans*ans2;
    ans3 = ans3%private_n;
    //alloc and copy
    char *temp = (char *)malloc((i+2)*sizeof(char));
    for (int j = 0; j < i; j++){
      temp[j] = decrypt[j];
    }
    temp[i] = (char)ans3;
    temp[i + 1] = '\0';
    if (decrypt != NULL){ free(decrypt); }
    decrypt = temp;
  }
  return decrypt;
}
