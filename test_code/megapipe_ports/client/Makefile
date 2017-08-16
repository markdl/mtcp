# Makefile for client

MTCP_INSTALL=/home/utcpdev/mtcp/mtcp
DPDK_INSTALL=/home/utcpdev/mtcp/dpdk

CC = gcc
CFLAGS = -Wall -Werror -fgnu89-inline
LDFLAGS= -pthread

DPDK_MACHINE_FLAGS = $(shell cat ${DPDK_INSTALL}/include/cflags.txt)
DPDK_LIB_FLAGS = $(shell cat ${DPDK_INSTALL}/lib/ldflags.txt)
INCL=-I${SSL_INSTALL}/include -I${MTCP_INSTALL}/include -I${MTCP_UTIL}/include -I${DPDK_INSTALL}/include

LIBS=-ldl -L${MTCP_INSTALL}/lib -L${DPDK_INSTALL}/lib -L${DPDK_INSTALL}/lib -lmtcp -lpthread -lnuma ${DPDK_LIB_FLAGS}

all: client client-ports client-mtcp

client: client.c client.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ client.c

client-ports: client-ports.c client.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ client-ports.c

client-mtcp: client-mtcp.c client-mtcp.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCL) -o $@ client-mtcp.c $(LIBS) 

clean:
	rm -rf client client-ports client-mtcp

