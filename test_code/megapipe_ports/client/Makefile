# Makefile for client

CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS= -pthread

all: client client-ports

client: client.c client.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ client.c

client-ports: client-ports.c client.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ client-ports.c

clean:
	rm -rf client client-ports

