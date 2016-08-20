CC=gcc
CFLAGS=-g -c -O2

all: sender

sender: sender.o
	$(CC) sender.o -o sender -lpcap

sender.o: sender.c
	$(CC) $(CFLAGS) sender.c

clean:
	rm -rf *.o sender
