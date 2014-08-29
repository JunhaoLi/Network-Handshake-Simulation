#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

#include "csapp.h"
#include "RSA.h"
#include "DHK.h"


void* nodeTalk(void* args);
void* start_listen(void* args);

int main(int argc, char *argv[]){

  int target_port,local_port;
  char *target_ip,*local_ip;
  if(argc !=5){
	  printf("please enter arguments in format:./name target_ip,target_port,local_ip,local_port\n");
  }
  target_ip = argv[1]; // reserver ip information for future extension
  target_port = atoi(argv[2]);
  local_ip =argv[3];
  local_port = atoi(argv[4]);
  // printf("the target ip is :%s\nthe target port is:%d\n",target_ip,target_port);

  //start listening
  int args[2];
  args[0] = local_port;
  args[1] = target_port;
  pthread_t hear;
  Pthread_create(&hear,NULL,start_listen,(void*)args);
  Pthread_detach(hear);

  //create connectionfd with server
  int targetfd;
  targetfd = open_clientfd(target_ip,target_port);
  if(targetfd < 0){
    printf("targetfd error!\n");
    return EXIT_FAILURE;
   }
 
  char *cmd, *signature;
  //hand shake start

  //_____________send client hello infromation to server with protocol infromation_______________
  char content[MAXLINE];
  sprintf(content, "ClientHello,sslv2.0");
  rio_writen(targetfd,content,strlen(content));
  //receive response from server, confirm protocol
  int len;
  char answer[MAXLINE];
  len = rio_readp(targetfd,answer,MAXLINE);
  printf("content received from server is: %s\n",answer);
  if(strstr(answer,"ServerHello")!=NULL){
    printf("hello ends\n");
  }

  //______________________DH exchange___________________________
  int dh_g = 3;
  int dh_b = 7;
  int dh_a = 0;
  int *g_ptr = &dh_g;
  int *a_ptr = &dh_a;
  int *b_ptr = &dh_b;
  DH_change_client (targetfd, g_ptr, a_ptr,b_ptr);
  printf("After DH function: g is %d,a is %d,b is %d\n", dh_g, dh_a, dh_b);

 //receive ditial singature from server and authenticate
  len = rio_readp(targetfd,answer,MAXLINE);
    for(int i = 0;i<strlen(answer)-1;i++){
    answer[i] = answer[i]+dh_a;
  }
  cmd = strtok_r(answer,",",&signature);
  printf("signature is %s\n",signature);
  if(strcmp(signature,target_ip) == 0){
    printf("digital signature verified\n");
  }


  //create private key-public key pair and send public key to server uisng DH method
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
  
  
   memset(content,0,sizeof(content));
  sprintf(content,"ClientKeyExchange,RSA %d %d,TLSv1",p,q);
  for (int i = 0; i<strlen(content);i++){
    content[i] = content[i]+dh_a;
  }
  rio_writen(targetfd,content,strlen(content));


  //__________________first talk______________________
  //receive infromation from server and decryption by RSA method
  memset(answer, 0, sizeof(answer));
  len = rio_readp(targetfd,answer,MAXLINE);
  char count_buffer[MAXLINE];
  memset(count_buffer, 0, sizeof(count_buffer));
  len = rio_readp(targetfd, count_buffer, MAXLINE);
  int word_count = atoi(count_buffer);
  printf("word count is: %d\n", word_count);
  char *decrypt = NULL;
  long long *ip2 = (long long *)answer;
  decrypt = decryption(ip2, word_count, private_n);
  printf("After decryption:%s\n", decrypt);



  //______________second talk_______________________
  memset(content,0,sizeof(content));
  sprintf(content,"ClientFinish");
  //encryption
  int ans_len = strlen(content);
  long long *ip = NULL;
  word_count = 0;
  int *word_count_ptr = &word_count;
  ip = encryption(content,ans_len, word_count_ptr, public_e, public_n);
  printf("Before encryption: %s\n", content);
  printf("After encryption,send:");
  char *ch = (char*)ip;
  printf("%s\n", ch);
//send content
  rio_writen(targetfd,ch,sizeof(ch)*word_count);
  //send word count
  memset(content, 0, sizeof(content));
  sprintf(content, "%d", word_count);
  printf("word count: %s\n", content);
  rio_writen(targetfd, content, sizeof(content));
  memset(content, 0, sizeof(content));
  printf("===============hand shake ends==================\n");
 
 
  printf("please input your message now\n\n");
  //start talking
  while (1){
    //send information to server
    printf("Client:");
    memset(content, 0, sizeof(content));
    scanf("%s", content);
    ans_len = strlen(content);
    ip = NULL;
    word_count = 0;
    word_count_ptr = &word_count;
    ip = encryption(content, ans_len, word_count_ptr, public_e, public_n);;
    char *ch = (char*)ip;
    //send content
    rio_writen(targetfd, ch, sizeof(ch)*word_count);
    //send word count
    memset(content, 0, sizeof(content));
    sprintf(content, "%d", word_count);
    rio_writen(targetfd, content, sizeof(content));
    memset(content, 0, sizeof(content));
    
    
    //receive information from server
    printf("Server:");
    memset(answer, 0, sizeof(answer));
    len = rio_readp(targetfd, answer, MAXLINE);
    if (strcmp(answer, "You end the talk. Sever disconnect.") == 0){
      printf("%s\n", answer);
      break;
    }
    memset(count_buffer, 0, sizeof(count_buffer));
    len = rio_readp(targetfd, count_buffer, MAXLINE);
    word_count = atoi(count_buffer);
    decrypt = NULL;
    ip2 = (long long *)answer;
    decrypt = decryption(ip2, word_count, private_n);
    printf("%s\n", decrypt);
  }
  close (targetfd);
  return EXIT_SUCCESS;
}



void* start_listen(void* args){
  int listenfd,optval;
  struct sockaddr_in clientaddr;
  struct hostent *hp;
  socklen_t clientlen;
  int lisfd;
  pthread_t tid;
  int args1[2];
  int local_port = ((int*)args)[0];
  int target_port = ((int*)args)[1];
  listenfd = open_listenfd(local_port);
  optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,(const void*)&optval,sizeof(int)); 

  while(1){
    clientlen = sizeof(clientaddr);
    lisfd = accept(listenfd, (SA*)&clientaddr,&clientlen);
    hp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,sizeof(clientaddr.sin_addr.s_addr),AF_INET);
    args1[0] = lisfd;
    args1[1] = target_port;
    Pthread_create(&tid,NULL,nodeTalk,(void*)args1);
    Pthread_detach(tid);
  }
}

void *nodeTalk(void* args){
  int numBytes,clientfd,Bport;
  rio_t client;
  int num;
  clientfd = ((int*)args)[0];
  Bport = ((int*)args)[1];
  num = ((int*)args)[2];
  rio_readinitb(&client,clientfd);
  char request[MAXLINE];

  numBytes = rio_readp(clientfd,request,MAXLINE);
  printf("message received through listening port is %s\n",request);
  char ans[MAXLINE];
  sprintf(ans,"hello client this is server");
  rio_writen(clientfd,ans,sizeof(ans));

  close(clientfd);
  return NULL;
}
