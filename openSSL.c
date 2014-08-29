/* this is not a working program yet, but should help you get started */


#include <stdio.h>
#include "csapp.h"
#include "proxy.h"
#include <pthread.h>
#include <string.h>  
#include <errno.h>  
#include <sys/socket.h>  
#include <resolv.h>  
#include <stdlib.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <openssl/ssl.h>  
#include <openssl/err.h>  




#define   LOG_FILE      "proxy.log"
#define   DEBUG_FILE"proxy.debug"

/*============================================================
 * function declarations
 *============================================================*/



struct _data{
  SSL *ssl;
  int cfd;
};
typedef struct _data data;

int  find_target_address(char * uri,
			 char * target_address,
			 char * path,
			 int  * port);


void  format_log_entry(char * logstring,
		       int sock,
		       char * uri,
		       int size);
       
void *webTalk(void* args);
void secureTalk(int clientfd, rio_t client, char *host, char *version, int serverPort);
void ignore();


  
void ShowCerts(SSL * ssl)  
{  
  X509 *cert;  
  char *line;  
  
  cert = SSL_get_peer_certificate(ssl);  
  if (cert != NULL) {  
    printf("Digital certificate information:\n");  
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
    printf("Certificate: %s\n", line);
    line = NULL;  
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);  
    printf("Issuer: %s\n", line);    
    X509_free(cert);  
  }  
  else  
    printf("No certificate information！\n");  
}  


int debug;
int proxyPort;
int debugfd;
int logfd;
pthread_mutex_t mutex;

/* main function for the proxy program */

int main(int argc, char *argv[])
{
  int count = 0;
  int listenfd, connfd, clientlen, optval, serverPort, i;
  struct sockaddr_in clientaddr;
  struct hostent *hp;
  char *haddrp;
  sigset_t sig_pipe;
  pthread_t tid;
  void *args;

  SSL_library_init();  
  OpenSSL_add_all_algorithms();  
  SSL_load_error_strings();  

  
  if (argc < 2) {
    printf("Usage: ./%s port [debug] [serverport]\n", argv[0]);
    exit(1);
  }
 
  proxyPort = atoi(argv[1]);

  /* turn on debugging if user enters a 1 for the debug argument */

  if(argc > 2)
    debug = atoi(argv[2]);
  else
    debug = 0;

  if(argc == 4)
    serverPort = atoi(argv[3]);
  else
    serverPort = 80;

  /* deal with SIGPIPE */
  
  Signal(SIGPIPE, ignore);
  
  if(sigemptyset(&sig_pipe) || sigaddset(&sig_pipe, SIGPIPE))
    unix_error("creating sig_pipe set failed");

  if(sigprocmask(SIG_BLOCK, &sig_pipe, NULL) == -1)
    unix_error("sigprocmask failed");

  /* important to use SO_REUSEADDR or can't restart proxy quickly */
  
  listenfd = Open_listenfd(proxyPort);
  optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int)); 
  
  if(debug) debugfd = Open(DEBUG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);

  logfd = Open(LOG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);    
  
  /* protect log file with a mutex */

  pthread_mutex_init(&mutex, NULL);
  

  /* not wait for new requests from browsers */

  while(1) {
    clientlen = sizeof(clientaddr);

    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    
    hp = Gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
		       sizeof(clientaddr.sin_addr.s_addr), AF_INET);

    haddrp = inet_ntoa(clientaddr.sin_addr);
     
    args = malloc(2*sizeof(int));
    ((int*)args)[0] = connfd; ((int*)args)[1] = serverPort;

    /* spawn a thread to process the new connection */

    Pthread_create(&tid, NULL, webTalk, (void*) args);
    Pthread_detach(tid);
  }


  /* should never get here, but if we do, clean up */

  Close(logfd);  
  if(debug) Close(debugfd);

  pthread_mutex_destroy(&mutex);
  
}

void parseAddress(char* url, char* host, char** file, int* serverPort)
{
  char buf[MAXLINE];
  char* point1;
  char *point2=NULL;

  if(strstr(url, "http://"))
    url = &(url[7]);
  *file = strchr(url, '/');
  
  strcpy(buf, url);
  point1 = strchr(url, ':');
  strcpy(host,buf);
  strtok_r(host,":/",&point2);

  if(!point1) {
    *serverPort = 80;
    return;
  }
  *serverPort = atoi(strtok_r(NULL, ":/",&point2));
  if(*serverPort==0){
    *serverPort = 80;
    return;
  }
}


/* WebTalk()
 *
 * Once a connection has been established, webTalk handles
 * the communication.
 */


/* this function is not complete */
/* you'll do the bulk of your work here */

void *webTalk(void* args)
{
  int numBytes, lineNum, serverfd, clientfd, serverPort;
  int tries;
  int byteCount = 0;
  char buf1[MAXLINE], buf2[MAXLINE], buf3[MAXLINE],buf4[MAXLINE];
  char url[MAXLINE], logString[MAXLINE];
  char host[MAXLINE];
  char *token, *cmd, *version, *file;
  rio_t server, client;
  char slash[10];
  char request[MAXLINE];
  strcpy(slash, "/");
  
  clientfd = ((int*)args)[0];
  serverPort = ((int*)args)[1];
  //free(args);
  rio_readinitb(&client, clientfd);//bind clientfd with client(rio_t) buffer
  /* Determine whether request is GET or CONNECT */
  numBytes = rio_readlineb(&client, buf1, MAXLINE);// read client request into buf1
  if(numBytes<=0){
    close(clientfd);
    return NULL;
  }
  if(strcmp(buf1, "\0") == 0) {
    close(clientfd);
    return NULL;
  }
  strcpy(buf2,buf1);
  char *str;
  cmd = strtok_r(buf1, " \r\n",&str);
  strcpy(url, strtok_r(NULL, " \r\n",&str));
  char v[MAXLINE];
  strcpy(v,strtok_r(NULL," \r\n",&str));
  parseAddress(url,host, &file, &serverPort); 
  if(!file) file = slash;
  if(debug) 
    {sprintf(buf3, "%s %s %i\n", host, file, serverPort); 
      Write(debugfd, buf3, strlen(buf3));}
  version = buf2;
  if(!strcmp(cmd, "CONNECT")) {
    secureTalk(clientfd, client, host, version, serverPort);
    return NULL; }
  else if(strcmp(cmd, "GET")) {
    close(clientfd);
    return NULL;
  }
  
  /* you should insert your code for processing connections here */
  ////////////////////////////////////////////////////////////////////////////
  int n=strlen("Connection: close\r\n");
  serverfd = open_clientfd(host,serverPort);
  if(serverfd<0){
    Close(clientfd);
    return NULL;
  }
  rio_writen(serverfd,buf2,numBytes);// send the data to server 
  while(1){
    numBytes = rio_readlineb(&client, buf4, MAXLINE);
    if(numBytes<=0){
      break;
    } 
    if(strstr(buf4,"Proxy-Connection: keep-alive")||strstr(buf4,"Connection: keep-alive")){
      strcpy(buf4,"Connection: close\r\n");
      numBytes = n;
    }
    rio_writen(serverfd,buf4,numBytes);// send the data to server 
    if(strcmp(buf4,"\r\n")==0){
      break;
    } 
  }
  int num;
  
  while(1){
    num = rio_readp(serverfd, buf4, MAXLINE);    
    if(num <= 0){
      break;
    }   
    rio_writen(clientfd,buf4,num);// send the data to client
  }// read data sent from server into buf2
 
    
  ///////////////////////////////////////////////////////////////////////////////
  /* code below writes a log entry at the end of processing the connection */
  
  
  /* 
     When EOF is detected while reading from the server socket,
     send EOF to the client socket by calling shutdown(clientfd,1);
     (and vice versa) 
  */
  
  Close(clientfd);
  Close(serverfd);
}

void *client_proxy(data *tran){
  printf("inside client_proxy\n");
  int len;
  char buf[MAXLINE]; 
  int cfd=tran->cfd;
  SSL *ssl = tran->ssl;
  while(1){
    len = SSL_read(ssl,buf,MAXLINE);
    printf("s to c:%s\n",buf);
    if(len<= 0){
      break; 
    }
    rio_writen(cfd,buf,len); 
  }
  return NULL;
}

void secureTalk(int clientfd, rio_t client, char *host, char *version, int serverPort){
 
  int serverfd;
  pthread_t cp;
  char url[MAXLINE], logString[MAXLINE]; 
  char buf1[MAXLINE],buf2[MAXLINE];
  int byteCount = 0;
  int num1,num2,num3;
  serverfd = open_clientfd(host,serverPort);  
  if(serverfd<0){
    close(clientfd);
    return;
  }

  SSL_CTX *ctx;  
  SSL *ssl;  
 
  ctx = SSL_CTX_new(SSLv23_client_method());  
  if (ctx == NULL)  
    {  
      ERR_print_errors_fp(stdout);  
      exit(1);  
    }  
  printf("SSL initial save 1\n");

  ssl = SSL_new(ctx);  
  SSL_set_fd(ssl, serverfd);
  printf("ssl bind to serverfd save\n");  
  /* åç SSL èæ */  
  if (SSL_connect(ssl) == -1)  
    ERR_print_errors_fp(stderr);  
  else  
    {  
      printf("Connected with %s encryption\n", SSL_get_cipher(ssl));  
      ShowCerts(ssl);  
    }  
  printf("ssl connection save\n");
  data tran;
  tran.ssl = ssl;
  tran.cfd = clientfd;  
  strcpy(buf2,"948676151.6444 (0.0005) C>S SSLv2 compatible client hello");
  strcpy(buf1, "HTTP/1.1 200 Connection established\r\n\r\n");
  rio_writen(clientfd,buf1,strlen(buf1));// send the data to client
  SSL_write(ssl,buf2,num1);
  Pthread_create(&cp, NULL, client_proxy,&tran);

  memset(buf1,0,sizeof(buf1));
  while(1){
    num1 = rio_readp(clientfd, buf1, MAXLINE); 
    printf("c to s:%s\n",buf1);
    SSL_write(ssl,buf1,num1);
    if(num1<=0){
      break;
    }
  }// send the data to server

  Pthread_detach(cp);
  Close(clientfd);      
  Close(serverfd);
}

void ignore()
{
  ;
}


/*============================================================
 * url parser:
 *    find_target_address()
 *        Given a url, copy the target web server address to
 *        target_address and the following path to path.
 *        target_address and path have to be allocated before they 
 *        are passed in and should be long enough (use MAXLINE to be 
 *        safe)
 *
 *        Return the port number. 0 is returned if there is
 *        any error in parsing the url.
 *
 *============================================================*/

/*find_target_address - find the host name from the uri */
int  find_target_address(char * uri, char * target_address, char * path,
                         int  * port)

{
 

  if (strncasecmp(uri, "http://", 7) == 0) {
    char * hostbegin, * hostend, *pathbegin;
    int    len;
       
    /* find the target address */
    hostbegin = uri+7;
    hostend = strpbrk(hostbegin, " :/\r\n");
    if (hostend == NULL){
      hostend = hostbegin + strlen(hostbegin);
    }
    
    len = hostend - hostbegin;

    strncpy(target_address, hostbegin, len);
    target_address[len] = '\0';

    /* find the port number */
    if (*hostend == ':')   *port = atoi(hostend+1);

    /* find the path */

    pathbegin = strchr(hostbegin, '/');

    if (pathbegin == NULL) {
      path[0] = '\0';
        
    }
    else {
      pathbegin++;
      strcpy(path, pathbegin);
    }
    return 0;
  }
  target_address[0] = '\0';
  return -1;
}



/*============================================================
 * log utility
 *    format_log_entry
 *       Copy the formatted log entry to logstring
 *============================================================*/

void format_log_entry(char * logstring, int sock, char * uri, int size)
{
  time_t  now;
  char    buffer[MAXLINE];
  struct  sockaddr_in addr;
  unsigned  long  host;
  unsigned  char a, b, c, d;
  int    len = sizeof(addr);

  now = time(NULL);
  strftime(buffer, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

  if (getpeername(sock, (struct sockaddr *) & addr, &len)) {
    unix_error("Can't get peer name");
  }

  host = ntohl(addr.sin_addr.s_addr);
  a = host >> 24;
  b = (host >> 16) & 0xff;
  c = (host >> 8) & 0xff;
  d = host & 0xff;

  sprintf(logstring, "%s: %d.%d.%d.%d %s %d\n", buffer, a,b,c,d, uri, size);
}
