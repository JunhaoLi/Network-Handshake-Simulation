#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "RSA.h"

int main() {
  int p = 11;
  int q = 19;
  int public_n;
  int public_e;
  int private_n;
  int private_d;
  int *public_n_ptr = &public_n;
  int *private_n_ptr = &private_n;
  int *public_e_ptr = &public_e;
  int *private_d_ptr = &private_d;
  
  RSA_generate(p,q,public_n_ptr,private_n_ptr,public_e_ptr,private_d_ptr);
  printf("public <n,e> = <%d,%d>\n", public_n, public_e);
  printf("private <n,d> = <%d,%d>\n", private_n, private_d);
  
  
  char content[] = "hi";
  int len = 3;
  long long *ip = NULL;
  int word_count = 0;
  int *word_count_ptr = &word_count;
  ip =encryption(content, len,word_count_ptr,public_e,public_n);
  printf("Before encryption: %s\n", content); 
  printf("After encryption:");
  for (int i = 0; i < word_count; i++){
    printf("%c ", (char)ip[i]);
  }
  printf("\n");
  
  char *decrypt = NULL;
  decrypt = decryption(ip, word_count,private_n);
  printf("After decryption: %s\n", decrypt); 
  return EXIT_SUCCESS;
}
