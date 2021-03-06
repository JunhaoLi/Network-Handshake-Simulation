#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "csapp.h"
#include "csapp.c"

void DH_change_server(int clientfd, int *dh_b, int *dh_a, int *dh_g){  //using diffie-hellman method to exchange key
	char request[MAXLINE];
	int numBytes = rio_readp(clientfd, request, MAXLINE);
	//printf("exchange: %s\n", request);
	int g = atoi(request);
	//printf("g is %d\n", g);
	char ans[MAXLINE];
	sprintf(ans, "%f", pow(g,*dh_a));
	rio_writen(clientfd, ans, sizeof(ans));
	memset(request, 0, sizeof(request));
	numBytes = rio_readp(clientfd, request, MAXLINE);
	int gb = atoi(request);
	double b = log(gb) / log(g);
	*dh_b =round(b);
	*dh_g =round(g);
}


void DH_change_client(int targetfd, int *dh_g, int *dh_a, int *dh_b){
	char content[MAXLINE];
	memset(content, 0, sizeof(content));
	sprintf(content, "%d", *dh_g);
	rio_writen(targetfd, content, strlen(content));
	//read ga
	char answer[MAXLINE];
	rio_readp(targetfd, answer, MAXLINE);
	int ga = atoi(answer);
	double aa = log(ga) / log(*dh_g);
	//send b
	sprintf(content, "%f", pow(*dh_g, *dh_b));
	rio_writen(targetfd, content, strlen(content));

	*dh_a =round(aa);
}




