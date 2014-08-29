
defaut:
	make server;
	make client;

server: server.c
	gcc -std=gnu99 -pedantic -Wall -pthread -lm -o server server.c
client: client.c	
	gcc -std=gnu99 -pedantic -Wall -pthread -lm -o client client.c
clean:
	rm -rf *.o
	rm server
	rm client
