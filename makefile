all: client server

client: client.o crypto.o utility.o
	gcc -Wall client.o -o client -lcrypto
	
server: server.o crypto.o utility.o
	gcc -Wall server.o -o server -lcrypto -pthread
	
prova: prova.o
	gcc -Wall prova.o -o prova 
	
clean:
	rm *.o client server
	


