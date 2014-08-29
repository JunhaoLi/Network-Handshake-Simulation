#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

#include "csapp.h"
#include "RSA.h"
#include "DHK.h"


int main(int argc, char *argv[]){
	
  int local_port;
  char *local_ip;
  if(argc != 3){
   printf("please enter arguments in format: ./name local_ip local_port\n");
  }
  local_ip = argv[1];  // reserver ip information for future extension
  local_port = atoi(argv[2]);
	
  //start listening
  int listenfd;
  listenfd = open_listenfd(local_port);
  int optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,(const void*)&optval,sizeof(int)); 
  struct sockaddr_in clientaddr;
  socklen_t clientlen;
  clientlen = sizeof(clientaddr);
  int clientfd;
  clientfd = accept(listenfd, (SA*)&clientaddr,&clientlen);
  struct hostent *hp;
  hp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,sizeof(clientaddr.sin_addr.s_addr),AF_INET);

  //hand shake start
  char ans[MAXLINE];
  char request[MAXLINE];
	//______________________hello message________________________
  rio_t  client;
  rio_readinitb(&client, clientfd);
  int numBytes;
  numBytes = rio_readp(clientfd, request, MAXLINE);
  printf("message received: %s\n\n", request);
  //check hello message and send to server
  if(strstr(request,"ClientHello")!=NULL){
      sprintf(ans,"ServerHello,sslv2.0");
      rio_writen(clientfd,ans,sizeof(ans));
  }

  //______________________DH exchange___________________________
  memset(request, 0, sizeof(request));
  int dh_g = 0;
  int dh_a = 5;
  int dh_b = 0;
  int *dh_g_ptr =&dh_g;
  int *dh_a_ptr =&dh_a;
  int *dh_b_ptr =&dh_b;
  DH_change_server(clientfd,dh_b_ptr,dh_a_ptr,dh_g_ptr);
  printf("After DH function: g is %d,a is %d,b is %d\n", dh_g, dh_a, dh_b);

  //___________________digital signature____________________________
  sprintf(ans,"digital signature,%s",local_ip);
  //use DH to cipher the signature
  for(int i = 0;i<strlen(ans)-1;i++){
    ans[i] = ans[i]-dh_a;
  }
  rio_writen(clientfd,ans,sizeof(ans));
  
  
  //__________________receive RSA p q_____________________________
  numBytes = rio_readp(clientfd,request,MAXLINE);
  for(int i = 0;i<strlen(request)-1;i++){
    request[i] = request[i]-dh_a;  
  }
  printf("after decipher is %s\n",request);
  char *cmd;
  char *str;
  cmd = strtok_r(request,",",&str);
  char *cipher;
  cipher = strtok_r(NULL," ",&str);
  int rsa_p = atoi(strtok_r(NULL," ",&str));   //public_n
  int rsa_q = atoi(strtok_r(NULL,",",&str));   //public_e
  int p = rsa_p;
  int q = rsa_q;
  int public_n;
  int public_e;
  int private_n;
  int private_d;
  int *public_n_ptr = &public_n;
  int *private_n_ptr = &private_n;
  int *public_e_ptr = &public_e;
  int *private_d_ptr = &private_d;

  RSA_generate(p, q, public_n_ptr, private_n_ptr, public_e_ptr, private_d_ptr);
  printf("public <n,e> = <%d,%d>\n", public_n, public_e);
  printf("private <n,d> = <%d,%d>\n", private_n, private_d);

  memset(ans,0,sizeof(ans));
  sprintf(ans,"ServerFinish");
  

  //__________________first talk_____________________
  //use RSA to cipher the signature
  int ans_len = strlen(ans);
  long long *ip = NULL;
  int word_count = 0;
  int *word_count_ptr = &word_count;
  ip = encryption(ans, ans_len, word_count_ptr, public_e, public_n);
  printf("Before encryption: %s\n", ans);
  printf("After encryption");
  char *ch = (char*)ip;
  printf("%s\n", ch);
  // send ip as char* array
  rio_writen(clientfd, ch, word_count*sizeof(ch));
  memset(ans, 0, sizeof(ans));
  //send word_count
  sprintf(ans, "%d", word_count);
  printf("word count:%s\n",ans);
  rio_writen(clientfd, ans, sizeof(ans));
  memset(ans, 0, sizeof(ans));
  //end singature


  //_____________second talk_______________
  //receive response from client
  memset(request,0,sizeof(request));
  numBytes = rio_readp(clientfd,request,MAXLINE);
  long long *ip2 = NULL;
  ip2 = (long long *)request;
  //receive word count
  char count_buffer[MAXLINE];
  memset(count_buffer, 0, sizeof(count_buffer));
  numBytes = rio_readp(clientfd, count_buffer, MAXLINE);
  word_count = atoi(count_buffer);
  char *decrypt = decryption(ip2, word_count, private_n);
  printf("Receive from client: %s\n", decrypt);
  printf("=============hand shake ends===========\n");
  
  
  //start talking
  while (1){
    //receive from client
    memset(request, 0, sizeof(request));
    numBytes = rio_readp(clientfd, request, MAXLINE);
    ip2 = (long long *)request;
    //receive word count
    memset(count_buffer, 0, sizeof(count_buffer));
    numBytes = rio_readp(clientfd, count_buffer, MAXLINE);
    word_count = atoi(count_buffer);
    char *decrypt = decryption(ip2, word_count, private_n);
    printf("word count: %d\n",word_count);
    printf("Client: %s\n", decrypt);
    if (strcmp(decrypt, "quit") == 0){
      //send last message without encryption
      memset(request, 0, sizeof(request));
      sprintf(request, "You end the talk. Sever disconnect.");
      rio_writen(clientfd, request, MAXLINE);
      break;
    }
    
    //send information to client
    printf("Server:");
    memset(ans, 0, sizeof(ans));
    scanf("%s", ans);
    ans_len = strlen(ans);
    ip = NULL;
    word_count = 0;
    word_count_ptr = &word_count;
    ip = encryption(ans, ans_len, word_count_ptr, public_e, public_n);
    ch = (char*)ip;
    // send ip as char* array
    rio_writen(clientfd, ch, word_count*sizeof(ch));
    memset(ans, 0, sizeof(ans));
    //send word_count
    sprintf(ans, "%d", word_count);
    rio_writen(clientfd, ans, sizeof(ans));
    memset(ans, 0, sizeof(ans));
  }
  close(clientfd);
  return EXIT_SUCCESS;
}
