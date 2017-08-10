SSL_INSTALL=/home/utcpdev/openssl/install
MTCP_INSTALL=/home/utcpdev/mtcp/mtcp
DPDK_INSTALL=/home/utcpdev/mtcp/dpdk
MTCP_UTIL=/home/utcpdev/mtcp/util

MTCP_UTIL_OBJ=$(addprefix $(MTCP_UTIL)/,http_parsing.o tdate_parse.o netlib.o)

CC=gcc -g -O0 -Wall -Werror -fgnu89-inline
DPDK_MACHINE_FLAGS = $(shell cat ${DPDK_INSTALL}/include/cflags.txt)
DPDK_LIB_FLAGS = $(shell cat ${DPDK_INSTALL}/lib/ldflags.txt)
INCL=-I${SSL_INSTALL}/include -I${MTCP_INSTALL}/include -I${MTCP_UTIL}/include -I${DPDK_INSTALL}/include

LIBS=-ldl -L${MTCP_INSTALL}/lib -L${DPDK_INSTALL}/lib -L${DPDK_INSTALL}/lib -lmtcp -lpthread -lnuma ${DPDK_LIB_FLAGS}

TARGETS = server-linux server-mtcp

all: ${TARGETS}

%.o: %.c
	${CC} -c $^ ${INCL} -o $@

server-mtcp.o: server-mtcp.c
	${CC} -c $^ ${INCL} -o $@

server-mtcp: server-mtcp.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

server-linux.o: server-linux.c
	${CC} -c $^ ${INCL} -o $@

server-linux: server-linux.o
	${CC} $^ ${LIBS} ${MTCP_UTIL_OBJ} -o $@

clean:
	rm -f *.o *~ \#*\# ${TARGETS}
